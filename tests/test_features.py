# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from duvora import server as server_module
from duvora.auth import DEFAULT_ADMIN_PASSWORD, LOGIN_FAILURES
from duvora.core import Problem, Store
from duvora.server import Application, handler


class StoreFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / 'state.db'), demo=True)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_admin_bootstrap_with_default_password(self):
        users = self.store.users()
        self.assertEqual([(u['username'], u['role'], u['default_password']) for u in users], [('admin', 'admin', True)])
        raw, user = self.store.login('admin', DEFAULT_ADMIN_PASSWORD)
        self.assertEqual(self.store.session_user(raw)['username'], 'admin')
        self.store.logout(raw)
        self.assertIsNone(self.store.session_user(raw))

    def test_bootstrap_honours_environment_password(self):
        with patch.dict('os.environ', {'DUVORA_ADMIN_PASSWORD': 'correct-horse-battery'}):
            store = Store(str(Path(self.tmp.name) / 'other.db'))
        try:
            with self.assertRaises(Problem):
                store.login('admin', DEFAULT_ADMIN_PASSWORD)
            self.assertFalse(store.users()[0]['default_password'])
            store.login('admin', 'correct-horse-battery')
        finally:
            store.close()

    def test_wrong_password_and_rate_limit(self):
        for _ in range(LOGIN_FAILURES):
            with self.assertRaises(Problem) as exc:
                self.store.login('admin', 'nope-nope', client='10.0.0.9')
            self.assertEqual(exc.exception.status, 401)
        with self.assertRaises(Problem) as exc:
            self.store.login('admin', DEFAULT_ADMIN_PASSWORD, client='10.0.0.9')
        self.assertEqual(exc.exception.status, 429)
        self.store.login('admin', DEFAULT_ADMIN_PASSWORD, client='10.0.0.10')
        self.assertTrue(any(a['action'] == 'session.failed' for a in self.store.snapshot()['audit']))

    def test_user_lifecycle_and_last_admin(self):
        self.store.create_user('admin', {'username': 'alice', 'role': 'viewer', 'password': 'alice-password'})
        with self.assertRaises(Problem):
            self.store.create_user('admin', {'username': 'alice', 'role': 'viewer', 'password': 'alice-password'})
        with self.assertRaises(Problem):
            self.store.create_user('admin', {'username': 'Bob!', 'role': 'viewer', 'password': 'bob-password'})
        with self.assertRaises(Problem):
            self.store.create_user('admin', {'username': 'bob', 'role': 'root', 'password': 'bob-password'})
        with self.assertRaises(Problem):
            self.store.create_user('admin', {'username': 'bob', 'role': 'viewer', 'password': 'short'})
        raw, _ = self.store.login('alice', 'alice-password')
        self.store.update_user('admin', 'alice', {'disabled': True})
        self.assertIsNone(self.store.session_user(raw))
        with self.assertRaises(Problem):
            self.store.login('alice', 'alice-password')
        with self.assertRaisesRegex(Problem, 'administrator'):
            self.store.update_user('admin', 'admin', {'role': 'viewer'})
        with self.assertRaisesRegex(Problem, 'administrator'):
            self.store.delete_user('admin', 'admin')
        self.store.delete_user('admin', 'alice')
        self.assertEqual([u['username'] for u in self.store.users()], ['admin'])

    def test_change_password_clears_default_flag(self):
        with self.assertRaises(Problem):
            self.store.change_password('admin', {'current': 'wrong-one', 'new': 'new-password-1'})
        user = self.store.change_password('admin', {'current': DEFAULT_ADMIN_PASSWORD, 'new': 'new-password-1'})
        self.assertFalse(user['default_password'])
        self.store.login('admin', 'new-password-1')

    def test_api_tokens(self):
        created = self.store.create_token('admin', {'name': 'cli'})
        self.assertTrue(created['token'].startswith('dvr_'))
        self.assertEqual(self.store.token_user(created['token'])['username'], 'admin')
        self.assertEqual([t['name'] for t in self.store.tokens('admin')], ['cli'])
        self.store.revoke_token('admin', created['id'])
        self.assertIsNone(self.store.token_user(created['token']))

    def test_history_records_and_downsamples(self):
        now = time.time() // 300 * 300 + 1
        self.store.simulate_metrics(now)
        self.store.simulate_metrics(now + 11)
        hist = self.store.history('bf3-01', '1h')
        self.assertEqual(len(hist['points']), 2)
        self.assertIn('throughput_gbps', hist['points'][0])
        self.assertEqual(self.store.device('bf3-01')['version'], 1)
        self.assertEqual(len(self.store.history('bf3-01', '24h')['points']), 1)
        with self.assertRaises(Problem):
            self.store.history('bf3-01', '1y')
        with self.assertRaises(Problem):
            self.store.history('missing', '1h')

    def test_report_records_sample(self):
        self.store.report('agent:node-a', {'id': 'pci-1', 'host': 'node-a', 'source': 'linux-pci', 'metrics': {'drops': 2}})
        self.assertEqual(self.store.history('pci-1')['points'][0]['drops'], 2)

    def test_alerts_open_ack_and_auto_resolve(self):
        self.store.evaluate_alerts(force=True)
        active = self.store.incidents('active')
        rules = {(i['rule'], i['target']) for i in active}
        self.assertIn(('health-degraded', 'bf3-03'), rules)
        self.assertIn(('packet-drops', 'bf3-03'), rules)
        self.store.evaluate_alerts(force=True)
        self.assertEqual(len(self.store.incidents('active')), len(active))
        inc = next(i for i in active if i['rule'] == 'health-degraded')
        self.assertEqual(self.store.incident_action('admin', inc['id'], 'ack')['state'], 'acknowledged')
        d = self.store.device('bf3-03'); d['health'] = 'healthy'; self.store.put('devices', 'bf3-03', d)
        self.store.evaluate_alerts(force=True)
        resolved = next(i for i in self.store.incidents('resolved') if i['id'] == inc['id'])
        self.assertEqual(resolved['resolved_by'], 'alerts')

    def test_rule_update_and_stale_rule(self):
        self.store.update_rule('admin', 'temperature-high', {'threshold': 40})
        self.store.update_rule('admin', 'packet-drops', {'enabled': False})
        with self.assertRaises(Problem):
            self.store.update_rule('admin', 'health-degraded', {'threshold': 1})
        with self.assertRaises(Problem):
            self.store.update_rule('admin', 'temperature-high', {'severity': 'loud'})
        self.store.report('agent:node-a', {'id': 'pci-1', 'host': 'node-a', 'source': 'linux-pci', 'metrics': {}})
        d = self.store.device('pci-1'); d['last_seen'] = time.time() - 500; self.store.put('devices', 'pci-1', d)
        self.store.evaluate_alerts(force=True)
        rules = {(i['rule'], i['target']) for i in self.store.incidents('active')}
        self.assertIn(('temperature-high', 'bf3-01'), rules)
        self.assertIn(('device-stale', 'pci-1'), rules)
        self.assertNotIn('packet-drops', {r for r, _ in rules})

    def test_scorecard_report_topology(self):
        self.store.evaluate_alerts(force=True)
        card = self.store.scorecard()
        self.assertTrue(0 <= card['score'] <= 100)
        self.assertEqual(sum(p['weight'] for p in card['parts']), 100)
        report = self.store.briefing()
        self.assertIn('# Duvora shift briefing', report['markdown'])
        self.assertEqual(report['fleet']['total'], 4)
        topo = self.store.topology()
        kinds = {n['kind'] for n in topo['nodes']}
        self.assertEqual(kinds, {'site', 'host', 'dpu'})
        self.assertEqual(sum(e['kind'] == 'hosts' for e in topo['edges']), 4)

    def test_empty_fleet_scorecard(self):
        store = Store(str(Path(self.tmp.name) / 'empty.db'))
        try:
            self.assertIsNone(store.scorecard()['score'])
        finally:
            store.close()

    def test_housekeeping_retention(self):
        plan = self.store.plan('admin', {'action': 'release', 'devices': ['bf3-01']})
        self.store.db.execute('UPDATE plans SET expires=? WHERE id=?', (time.time() - 7200, plan['id']))
        self.store.db.execute('INSERT INTO samples(device,ts,metrics) VALUES(?,?,?)', ('bf3-01', time.time() - 8 * 86400, '{}'))
        removed = self.store.housekeeping()
        self.assertEqual(removed['plans'], 1)
        self.assertEqual(removed['samples'], 1)

    def test_backup_is_valid_database(self):
        data = self.store.backup('admin')
        path = Path(self.tmp.name) / 'copy.db'
        path.write_bytes(data)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM devices').fetchone()[0], 4)


class SessionHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.static = Path(cls.tmp.name) / 'static'
        (cls.static / 'assets').mkdir(parents=True)
        (cls.static / 'index.html').write_text('<!doctype html><title>Duvora</title><div id="root"></div>')
        (cls.static / 'assets' / 'app-123.js').write_text('console.log(1)')
        cls.patch = patch.object(server_module, 'STATIC', cls.static)
        cls.patch.start()
        cls.store = Store(str(Path(cls.tmp.name) / 'http.db'), demo=True)
        cls.app = Application(cls.store, {'agent:node-a': ('agent', 'n' * 24)})
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), handler(cls.app))
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.thread.join(); cls.server.server_close()
        cls.store.close(); cls.patch.stop(); cls.tmp.cleanup()

    def http(self, method, path, body=None, cookie=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if cookie:
            headers['Cookie'] = cookie
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers, exc.read()

    def login(self, username='admin', password=DEFAULT_ADMIN_PASSWORD):
        status, headers, body = self.http('POST', '/api/v1/session', {'username': username, 'password': password})
        self.assertEqual(status, 200, body)
        cookie = headers['Set-Cookie']
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        return cookie.split(';')[0]

    def test_login_session_whoami_logout(self):
        cookie = self.login()
        status, _, body = self.http('GET', '/api/v1/whoami', cookie=cookie)
        who = json.loads(body)
        self.assertEqual((status, who['actor'], who['role'], who['via']), (200, 'admin', 'admin', 'session'))
        self.assertTrue(who['default_password'])
        self.assertEqual(self.http('GET', '/api/v1/snapshot', cookie=cookie)[0], 200)
        self.assertEqual(self.http('DELETE', '/api/v1/session', cookie=cookie)[0], 200)
        self.assertEqual(self.http('GET', '/api/v1/whoami', cookie=cookie)[0], 401)

    def test_wrong_password(self):
        status, _, body = self.http('POST', '/api/v1/session', {'username': 'admin', 'password': 'wrong-password'})
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'Wrong username or password.')

    def test_user_management_over_http(self):
        cookie = self.login()
        status, _, _ = self.http('POST', '/api/v1/users', {'username': 'carol', 'role': 'viewer', 'password': 'carol-password'}, cookie=cookie)
        self.assertEqual(status, 200)
        viewer = self.login('carol', 'carol-password')
        self.assertEqual(self.http('GET', '/api/v1/users', cookie=viewer)[0], 403)
        self.assertEqual(self.http('POST', '/api/v1/plans', {'action': 'release', 'devices': ['bf3-01']}, cookie=viewer)[0], 403)
        self.assertEqual(self.http('PATCH', '/api/v1/users/carol', {'role': 'admin'}, cookie=cookie)[0], 200)
        self.assertEqual(self.http('GET', '/api/v1/whoami', cookie=viewer)[0], 401)
        self.assertEqual(self.http('DELETE', '/api/v1/users/carol', cookie=cookie)[0], 200)

    def test_token_flow_for_cli(self):
        cookie = self.login()
        status, _, body = self.http('POST', '/api/v1/tokens', {'name': 'duvoractl'}, cookie=cookie)
        token = json.loads(body)['token']
        status, _, body = self.http('GET', '/api/v1/whoami', token=token)
        self.assertEqual(json.loads(body)['via'], 'token')
        self.assertEqual(self.http('GET', '/api/v1/tokens', token='n' * 24)[0], 403)

    def test_feature_endpoints(self):
        cookie = self.login()
        self.store.simulate_metrics(time.time() + 3600)
        self.store.evaluate_alerts(force=True)
        for path in ['/api/v1/devices/bf3-01/history?window=1h', '/api/v1/incidents?state=active', '/api/v1/alert-rules',
                     '/api/v1/scorecard', '/api/v1/report', '/api/v1/topology']:
            status, _, body = self.http('GET', path, cookie=cookie)
            self.assertEqual(status, 200, path)
            json.loads(body)
        status, headers, body = self.http('GET', '/api/v1/report.md', cookie=cookie)
        self.assertIn('text/markdown', headers['Content-Type'])
        status, headers, body = self.http('GET', '/api/v1/backup', cookie=cookie)
        self.assertEqual(body[:15], b'SQLite format 3')
        self.assertIn('attachment', headers['Content-Disposition'])
        status, _, body = self.http('PUT', '/api/v1/alert-rules/temperature-high', {'threshold': 85}, cookie=cookie)
        self.assertEqual(json.loads(body)['threshold'], 85)
        self.assertEqual(self.http('GET', '/api/v1/incidents?state=bogus', cookie=cookie)[0], 400)
        self.assertEqual(self.http('PUT', '/api/v1/scorecard', {'x': 1}, cookie=cookie)[0], 405)

    def test_cli_login_writes_private_env_and_logout_revokes(self):
        from argparse import Namespace
        from duvora import cli
        env = Path(self.tmp.name) / 'cli-env'
        with patch.object(cli, 'ENV_FILE', env), patch.object(cli, 'prompt_password', return_value=DEFAULT_ADMIN_PASSWORD):
            result = cli.login(Namespace(url=self.url, user='admin'))
            self.assertEqual(result['signed_in'], 'admin')
            values = cli.read_env_file()
            self.assertEqual(env.stat().st_mode & 0o777, 0o600)
            self.assertEqual(values['DUVORA_URL'], self.url)
            token = values['DUVORA_TOKEN']
            self.assertEqual(cli.run(Namespace(url=self.url, command='whoami'), token)['via'], 'token')
            md = cli.run(Namespace(url=self.url, command='report', markdown=True), token)
            self.assertIn('# Duvora shift briefing', md)
            cli.logout(Namespace(url=self.url), token)
            self.assertNotIn('DUVORA_TOKEN', cli.read_env_file())
            self.assertIsNone(self.store.token_user(token))

    def test_agent_key_still_reports(self):
        status, _, _ = self.http('POST', '/api/v1/reports', {'id': 'pci-9', 'host': 'node-a', 'source': 'linux-pci'}, token='n' * 24)
        self.assertEqual(status, 200)
        self.assertEqual(self.http('GET', '/api/v1/snapshot', token='n' * 24)[0], 403)

    def test_spa_fallback_and_asset_cache(self):
        status, headers, body = self.http('GET', '/fleet/devices')
        self.assertEqual(status, 200)
        self.assertIn(b'id="root"', body)
        status, headers, _ = self.http('GET', '/assets/app-123.js')
        self.assertIn('immutable', headers['Cache-Control'])
        self.assertEqual(self.http('GET', '/assets/missing.js')[0], 404)
        self.assertEqual(self.http('GET', '/..%2f..%2fcore.py')[0], 404)


if __name__ == '__main__':
    unittest.main()
