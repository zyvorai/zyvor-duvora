# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from duvora.core import Problem, Store
from duvora.agent import discover
from duvora.dpf import convert
from duvora.server import Application, load_keys
from unittest.mock import patch


class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.db')
        self.store = Store(self.path, demo=True)
        self.spec = {'action': 'isolate', 'devices': ['bf3-01'], 'policy': {'name': 'private', 'tenant': 'tenant-a', 'cidr': '10.42.0.0/16', 'ports': [443]}}

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def run_job(self, spec=None):
        plan = self.store.plan('admin', spec or self.spec)
        job = self.store.apply('admin', plan['id'], 'APPLY SIMULATION')
        for _ in range(4):
            self.store.tick()
        return next(x for x in self.store.rows('jobs') if x['id'] == job['id'])

    def test_allow_list_and_release(self):
        self.run_job()
        self.assertEqual(self.store.evaluate('bf3-01', '10.42.1.1', 443)['verdict'], 'allow')
        self.assertEqual(self.store.evaluate('bf3-01', '10.42.1.1', 80)['verdict'], 'deny')
        self.assertEqual(self.store.evaluate('bf3-01', '8.8.8.8', 443)['verdict'], 'deny')
        self.run_job({'action':'release', 'devices':['bf3-01']})
        self.assertEqual(self.store.evaluate('bf3-01', '8.8.8.8', 443)['verdict'], 'allow')

    def test_rollback_isolation(self):
        job = self.run_job()
        self.store.rollback('admin', job['id'])
        self.assertEqual(self.store.device('bf3-01')['mode'], 'observe')
        self.assertEqual(self.store.rows('policies'), [])

    def test_rollback_release_restores_policy(self):
        self.run_job()
        job = self.run_job({'action':'release','devices':['bf3-01']})
        self.store.rollback('admin',job['id'])
        self.assertEqual(self.store.evaluate('bf3-01','8.8.8.8',443)['verdict'],'deny')

    def test_partial_release_preserves_other_members(self):
        self.spec['devices'] = ['bf3-01','bf3-02']
        self.run_job()
        job = self.run_job({'action':'release','devices':['bf3-01']})
        self.assertEqual(self.store.rows('policies')[0]['devices'], ['bf3-02'])
        self.store.rollback('admin',job['id'])
        self.assertEqual(self.store.rows('policies')[0]['devices'], ['bf3-01','bf3-02'])

    def test_immutable_image(self):
        with self.assertRaises(Problem):
            self.store.plan('admin', {'action':'deploy','devices':['bf3-01'],'service':'observer','image':'nginx:latest'})
        job=self.run_job({'action':'deploy','devices':['bf3-01'],'service':'observer','image':'registry.example/observer@sha256:'+'a'*64})
        self.assertEqual(job['state'],'succeeded')
        self.assertEqual(self.store.device('bf3-01')['services'][0]['state'],'simulated-running')

    def test_upgrade_and_rollback(self):
        job=self.run_job({'action':'upgrade','devices':['bf3-01'],'firmware':'demo-2.0'})
        self.assertEqual([x['step'] for x in job['events']], ['preflight','drain','update','verify'])
        self.assertEqual(self.store.device('bf3-01')['firmware'],'demo-2.0')
        self.store.rollback('admin',job['id'])
        self.assertEqual(self.store.device('bf3-01')['firmware'],'demo-1.0')

    def test_stale_plan_rejected(self):
        p=self.store.plan('admin', self.spec)
        self.run_job({'action':'upgrade','devices':['bf3-01'],'firmware':'demo-2.0'})
        with self.assertRaisesRegex(Problem,'state changed'):
            self.store.apply('admin', p['id'], 'APPLY SIMULATION')

    def test_expired_plan(self):
        p=self.store.plan('admin',self.spec)
        self.store.db.execute('UPDATE plans SET expires=0 WHERE id=?',(p['id'],))
        with self.assertRaisesRegex(Problem,'expired'):
            self.store.apply('admin',p['id'],'APPLY SIMULATION')

    def test_actor_bound_plan(self):
        p=self.store.plan('admin',self.spec)
        with self.assertRaises(Problem):
            self.store.apply('other',p['id'],'APPLY SIMULATION')

    def test_idempotent_apply(self):
        p=self.store.plan('admin',self.spec)
        a=self.store.apply('admin',p['id'],'APPLY SIMULATION')
        b=self.store.apply('admin',p['id'],'APPLY SIMULATION')
        self.assertEqual(a['id'],b['id'])
        self.assertEqual(len(self.store.rows('jobs')),1)

    def test_concurrent_apply_is_one_job(self):
        p=self.store.plan('admin',self.spec)
        results=[]
        threads=[threading.Thread(target=lambda:results.append(self.store.apply('admin',p['id'],'APPLY SIMULATION')['id'])) for _ in range(8)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(len(results),8)
        self.assertEqual(len(set(results)),1)

    def test_overlapping_jobs_rejected(self):
        a=self.store.plan('admin',self.spec); b=self.store.plan('admin',self.spec)
        self.store.apply('admin',a['id'],'APPLY SIMULATION')
        with self.assertRaisesRegex(Problem,'active job'):
            self.store.apply('admin',b['id'],'APPLY SIMULATION')

    def test_restart_resumes_queued_job(self):
        p=self.store.plan('admin',self.spec)
        self.store.apply('admin',p['id'],'APPLY SIMULATION');self.store.tick()
        self.store.close();self.store=Store(self.path,demo=True)
        for _ in range(3):self.store.tick()
        self.assertEqual(self.store.rows('jobs')[0]['state'],'succeeded')
        self.assertEqual(len(self.store.rows('devices')),4)

    def test_simulator_requires_explicit_mode_on_restart(self):
        p=self.store.plan('admin',self.spec)
        self.store.close();self.store=Store(self.path,demo=False)
        # An old preview must not enable simulation in a non-demo server.
        with self.assertRaises(Problem):
            self.store.apply('admin',p['id'],'APPLY SIMULATION')

    def report(self, **kwargs):
        return dict({'id':'pci-123','host':'node-a','site':'pune','source':'linux-pci','model':'BlueField-3','metrics':{}},**kwargs)

    def test_hardware_mutations_blocked(self):
        self.store.report('agent:node-a',self.report())
        p=self.store.plan('admin',{'action':'upgrade','devices':['pci-123'],'firmware':'demo-2.0'})
        self.assertTrue(p['blockers'])
        with self.assertRaisesRegex(Problem,'blocked'):
            self.store.apply('admin',p['id'],'APPLY SIMULATION')

    def test_agent_cannot_impersonate_other_host(self):
        with self.assertRaises(Problem):self.store.report('agent:node-b',self.report())

    def test_agent_cannot_replace_simulated_identity(self):
        with self.assertRaises(Problem):self.store.report('agent:node-a',self.report(id='bf3-01'))

    def test_agent_cannot_set_enforcement(self):
        with self.assertRaises(Problem):self.store.report('agent:node-a',self.report(mode='isolated'))

    def test_metrics_reject_non_finite(self):
        for value in [float('nan'),float('inf'),-1,True]:
            with self.assertRaises(Problem):self.store.report('agent:node-a',self.report(metrics={'drops':value}))

    def test_stale_observation(self):
        self.store.report('agent:node-a',self.report())
        d=self.store.device('pci-123');d['last_seen']=time.time()-121;self.store.put('devices',d['id'],d)
        self.assertEqual(next(x for x in self.store.snapshot()['devices'] if x['id']=='pci-123')['health'],'stale')

    def test_policy_validation(self):
        for cidr, ports in [('10.42.1.1/16',[443]),('bad',[443]),('10.0.0.0/8',[0]),('10.0.0.0/8',[True])]:
            spec=json.loads(json.dumps(self.spec));spec['policy']['cidr']=cidr;spec['policy']['ports']=ports
            with self.assertRaises(Problem):self.store.plan('admin',spec)

    def test_ipv6_evaluation(self):
        self.spec['policy']['cidr']='2001:db8::/32';self.run_job()
        self.assertEqual(self.store.evaluate('bf3-01','2001:db8::1',443)['verdict'],'allow')
        self.assertEqual(self.store.evaluate('bf3-01','10.0.0.1',443)['verdict'],'deny')

    def test_roles(self):
        app=Application(self.store,{'admin':('admin','a'*24),'viewer':('viewer','v'*24),'agent:node-a':('agent','n'*24)})
        self.assertEqual(app.identity('v'*24),('viewer','viewer'))
        with self.assertRaises(Problem):app.identity('invalid')
        self.assertTrue(app.dispatch('GET','/api/v1/snapshot','viewer','viewer')['devices'])
        with self.assertRaises(Problem):app.dispatch('POST','/api/v1/plans','viewer','viewer',self.spec)
        with self.assertRaises(Problem):app.dispatch('GET','/api/v1/snapshot','agent:node-a','agent')

    def test_rollback_cannot_overwrite_later_change(self):
        first=self.run_job()
        self.run_job({'action':'upgrade','devices':['bf3-01'],'firmware':'demo-2.0'})
        with self.assertRaisesRegex(Problem,'Later changes'):
            self.store.rollback('admin',first['id'])

    def test_invalid_keys(self):
        with patch.dict('os.environ',{'DUVORA_KEYS':json.dumps({'a':{'role':'admin','token':'x'*24},'b':{'role':'viewer','token':'x'*24}})}):
            with self.assertRaises(ValueError):load_keys()


class DiscoveryTests(unittest.TestCase):
    def test_pci_discovery(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'0000:03:00.0';p.mkdir();(p/'vendor').write_text('0x15b3');(p/'device').write_text('0xa2d3');(p/'net').mkdir();(p/'net'/'p0').mkdir()
            result=discover(Path(root),'node-a','pune')
            self.assertEqual(result[0]['model'],'BlueField-3');self.assertEqual(result[0]['metrics'],{})
            self.assertEqual(result[0]['health'],'unknown');self.assertEqual(result[0]['interfaces'],['p0'])
            self.assertEqual(result[0]['id'],discover(Path(root),'node-a','pune')[0]['id'])
            (p/'vendor').write_text('0x1234');self.assertEqual(discover(Path(root),'node-a'),[])

    def test_dpf_import(self):
        items=[{'metadata':{'uid':'dpu-uid'},'status':{'phase':'Ready'}}]
        report=convert(items,'bridge-a','pune')[0]
        self.assertEqual(report['health'],'healthy');self.assertEqual(report['metrics'],{})
        items[0]['status']['phase']='Error'
        self.assertEqual(convert(items,'bridge-a','pune')[0]['health'],'degraded')
        items[0]['status']['phase']='Initializing'
        self.assertEqual(convert(items,'bridge-a','pune')[0]['health'],'unknown')
        with self.assertRaises(ValueError):convert([{}],'bridge-a','pune')


if __name__=='__main__':unittest.main()
