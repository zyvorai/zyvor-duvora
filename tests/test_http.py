import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from duvora.core import Store
from duvora.server import Application, handler
from duvora.cli import request


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.store=Store(str(Path(cls.tmp.name)/'test.db'),demo=True)
        cls.app=Application(cls.store,{'admin':('admin','a'*24),'viewer':('viewer','v'*24),'agent:node-a':('agent','n'*24)})
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),handler(cls.app))
        cls.url=f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.thread.join();cls.server.server_close();cls.store.close();cls.tmp.cleanup()

    def call(self,path,token='a'*24,body=None):
        return request(self.url,token,path,body)

    def test_authenticated_snapshot(self):
        self.assertEqual(len(self.call('/api/v1/snapshot')['devices']),4)

    def test_unauthenticated_denied(self):
        with self.assertRaises(urllib.error.HTTPError) as exc:self.call('/api/v1/snapshot','wrong')
        self.assertEqual(exc.exception.code,401)

    def test_viewer_cannot_plan(self):
        with self.assertRaises(urllib.error.HTTPError) as exc:self.call('/api/v1/plans','v'*24,{'action':'release','devices':['bf3-01']})
        self.assertEqual(exc.exception.code,403)

    def test_kill_switch_admin_only(self):
        with self.assertRaises(urllib.error.HTTPError) as exc:self.call('/api/v1/ebpf/kill-switch','v'*24,{'engaged':True})
        self.assertEqual(exc.exception.code,403)
        self.assertTrue(self.call('/api/v1/ebpf/kill-switch',body={'engaged':True})['engaged'])
        self.assertTrue(self.call('/api/v1/ebpf')['netra']['kill_switch']['engaged'])
        self.assertFalse(self.call('/api/v1/ebpf/kill-switch',body={'engaged':False})['engaged'])

    def test_health_public(self):
        with urllib.request.urlopen(self.url+'/healthz') as r:self.assertEqual(json.load(r)['status'],'ok')

    def test_dashboard_and_security_headers(self):
        with urllib.request.urlopen(self.url+'/') as r:
            self.assertIn('default-src',r.headers['Content-Security-Policy'])
            self.assertEqual(r.headers['X-Frame-Options'],'DENY')
            self.assertIn(b'Duvora',r.read())

    def test_static_traversal_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as exc:urllib.request.urlopen(self.url+'/../core.py')
        self.assertEqual(exc.exception.code,404)

    def test_metrics(self):
        self.assertIn('duvora_devices{source="simulator"} 4',self.call('/api/v1/metrics'))

    def test_invalid_json(self):
        req=urllib.request.Request(self.url+'/api/v1/plans',data=b'{bad',headers={'Authorization':'Bearer '+'a'*24,'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as exc:urllib.request.urlopen(req)
        self.assertEqual(exc.exception.code,400)

    def test_wrong_content_type(self):
        req=urllib.request.Request(self.url+'/api/v1/plans',data=b'{}',headers={'Authorization':'Bearer '+'a'*24,'Content-Type':'text/plain'})
        with self.assertRaises(urllib.error.HTTPError) as exc:urllib.request.urlopen(req)
        self.assertEqual(exc.exception.code,415)

    def test_nonfinite_json(self):
        req=urllib.request.Request(self.url+'/api/v1/reports',data=b'{"metrics":{"drops":NaN}}',headers={'Authorization':'Bearer '+'n'*24,'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as exc:urllib.request.urlopen(req)
        self.assertEqual(exc.exception.code,400)

    def test_remote_http_blocked_in_client(self):
        with self.assertRaisesRegex(ValueError,'HTTPS'):request('http://example.com','token','/api/v1/snapshot')

    def test_export_round_trip(self):
        self.assertEqual(self.call('/api/v1/export')['version'],'0.5.0')

    def test_unknown_endpoint(self):
        with self.assertRaises(urllib.error.HTTPError) as exc:self.call('/api/v1/unknown')
        self.assertEqual(exc.exception.code,404)


if __name__=='__main__':unittest.main()
