# SPDX-License-Identifier: AGPL-3.0-only
"""Real TCP loopback + ephemeral TLS 1.3 mutual certs; no Git-tracked private keys."""
import hashlib
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest

from ryzova.remote.trust import Endpoint,PeerPolicy
from ryzova.remote.tlsloop import (
    TLSLoopbackClient,TLSLoopbackServer,TLSUnavailable,
    client_context,server_context)
from ryzova.remote.p9 import ReadOnly9PServer,ReadOnly9PClient
from ryzova.remote.cache import RemotePageCache
from ryzova.remote.compute import PureTaskClient,PureTaskServer
from ryzova.remote.recovery import RemoteCircuit,ServiceUnavailable

def _cert(dir,name):
    key=dir/(name+".key")
    cert=dir/(name+".pem")
    subject="localhost" if name=="server" else "ryzova-client"
    args=["openssl","req","-x509","-newkey","rsa:2048","-nodes",
          "-sha256","-days","1","-subj","/CN="+subject,
          "-keyout",str(key),"-out",str(cert)]
    if name=="server":
        args+=["-addext","subjectAltName=DNS:localhost,IP:127.0.0.1"]
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if p.returncode:
        raise AssertionError(p.stderr)
    return cert,key

def _fingerprint(cert):
    contents=ssl.PEM_cert_to_DER_cert(cert.read_text())
    return hashlib.sha256(contents).hexdigest()

class EndToEndTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("openssl") is None:
            raise RuntimeError("OpenSSL CLI needed to issue short-lived test certificates")
        cls.temp=tempfile.TemporaryDirectory(prefix="ryzova-tls-")
        path=Path(cls.temp.name)
        cls.servercert,cls.serverkey=_cert(path,"server")
        cls.clientcert,cls.clientkey=_cert(path,"client")
        cls.server_context=server_context(str(cls.servercert),str(cls.serverkey),str(cls.clientcert))
        cls.client_context=client_context(str(cls.clientcert),str(cls.clientkey),str(cls.servercert))
        cls.server_pin=_fingerprint(cls.servercert)
        cls.client_pin=_fingerprint(cls.clientcert)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def setup_pair(self,handlers):
        key=b"test-only-generated-never-ship-key!"  # test fixture: NOT production key
        client_ep=Endpoint("client",key,PeerPolicy(True,frozenset({"server"}),frozenset(handlers)))
        server_ep=Endpoint("server",key,PeerPolicy(True,frozenset({"client"}),frozenset(handlers)))
        return client_ep,server_ep
    def _server(self,handlers,server_ep):
        return TLSLoopbackServer(self.server_context,server_ep,handlers,self.client_pin)
    def _client(self,port,client_ep,ctx=None,pin=None,timeout=1.5):
        return TLSLoopbackClient(ctx or self.client_context,client_ep,
                                 pin or self.server_pin,port,timeout=timeout)
    def test_tls13_authenticated_real_tcp_9p_and_hash_pinned_cache(self):
        data=b"Z"*4096
        server9=ReadOnly9PServer({"page":data})
        client_ep,server_ep=self.setup_pair({"9p":server9.process})
        with self._server({"9p":server9.process},server_ep) as server:
            cli=self._client(server.port,client_ep)
            nine=ReadOnly9PClient(lambda raw:cli.request("9p",raw))
            cache=RemotePageCache(capacity_pages=2)
            got=cache.get("page",hashlib.sha256(data).hexdigest(),nine.read_file)
            self.assertEqual(got,data)
            self.assertEqual(server.denied,0)
            self.assertGreaterEqual(server.handled,6)
    def test_tls13_real_tcp_pure_compute(self):
        jobs=PureTaskServer(4)
        cli_ep,srv_ep=self.setup_pair({"compute":jobs.handle})
        with self._server({"compute":jobs.handle},srv_ep) as server:
            cli=PureTaskClient(self._client(server.port,cli_ep))
            self.assertEqual(cli.run({"op":"dot","a":[1,2,3],"b":[4,5,6]}),32)
            self.assertEqual(server.handled,1)
    def test_wrong_server_cert_pin_fails_closed(self):
        cli_ep,srv_ep=self.setup_pair({"compute":lambda b:b})
        with self._server({"compute":lambda b:b},srv_ep) as server:
            cli=self._client(server.port,cli_ep,pin="0"*64)
            with self.assertRaises(TLSUnavailable):cli.request("compute",b"hello")
    def test_missing_client_cert_rejected_by_mutual_tls(self):
        cli_ep,srv_ep=self.setup_pair({"compute":lambda b:b})
        bad=ssl.create_default_context(cafile=str(self.servercert))
        bad.minimum_version=ssl.TLSVersion.TLSv1_3
        with self._server({"compute":lambda b:b},srv_ep) as server:
            cli=self._client(server.port,cli_ep,ctx=bad)
            with self.assertRaises(TLSUnavailable):cli.request("compute",b"hello")
    def test_wrong_server_trust_fails_closed(self):
        cli_ep,srv_ep=self.setup_pair({"compute":lambda b:b})
        bad=client_context(str(self.clientcert),str(self.clientkey),str(self.clientcert))
        with self._server({"compute":lambda b:b},srv_ep) as server:
            with self.assertRaises(TLSUnavailable):
                self._client(server.port,cli_ep,ctx=bad).request("compute",b"x")
    def test_disconnect_trips_recovery_without_fabricated_success(self):
        cli_ep,srv_ep=self.setup_pair({"compute":lambda b:b})
        with self._server({"compute":lambda b:b},srv_ep) as server:
            port=server.port
        cli=self._client(port,cli_ep,timeout=.3)
        circuit=RemoteCircuit(cli,enabled=True,failure_threshold=1)
        with self.assertRaises(ServiceUnavailable):circuit.request("compute",b"hello")
        self.assertTrue(circuit.telemetry()["open"])
    def test_server_rejects_modified_hmac_inside_tls(self):
        client_ep,server_ep=self.setup_pair({"compute":lambda b:b})
        # A mismatched application HMAC secret must still fail despite valid TLS.
        wrong=Endpoint("client",b"wrong-application-test-key-32bytes",
                       PeerPolicy(True,frozenset({"server"}),frozenset({"compute"})))
        with self._server({"compute":lambda b:b},server_ep) as server:
            with self.assertRaises(TLSUnavailable):
                self._client(server.port,wrong).request("compute",b"bad")
            self.assertGreaterEqual(server.denied,1)
    def test_large_wire_request_rejected(self):
        cli_ep,srv_ep=self.setup_pair({"compute":lambda b:b})
        with self._server({"compute":lambda b:b},srv_ep) as server:
            with self.assertRaises(Exception):
                self._client(server.port,cli_ep).request("compute",b"x"*8193)
if __name__=="__main__":unittest.main()
