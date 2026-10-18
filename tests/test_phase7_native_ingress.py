# SPDX-License-Identifier: AGPL-3.0-only
"""Real TLS1.2 guest-facing 9P socket test with upstream mutual TLS1.3."""
import hashlib
import socket
import ssl
from pathlib import Path
import unittest
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from ryzova.remote.native_bridge import read_frame
from ryzova.remote.p9 import ReadOnly9PClient

class NativeIngressTests(unittest.TestCase):
    def test_tls12_server_pinned_upstream_mtls13_real_9p(self):
        data=b"source-guest-tls-data\n"
        with Ephemeral9PTLSFixture(data) as f:
            trusted=str(Path(f._directory.name)/"server.pem")
            ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=trusted)
            ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.maximum_version=ssl.TLSVersion.TLSv1_2
            with socket.create_connection(("127.0.0.1",f.guest_tls.server_address[1]),timeout=5) as raw:
                raw.settimeout(5)
                with ctx.wrap_socket(raw,server_hostname="localhost") as secure:
                    self.assertEqual(secure.version(),"TLSv1.2")
                    self.assertEqual(hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest(),
                                     f.guest_cert_sha256)
                    def exchange(req):
                        secure.sendall(req)
                        return read_frame(secure)
                    self.assertEqual(ReadOnly9PClient(exchange).read_file("probe"),data)
            self.assertGreaterEqual(f.guest_tls.tls12_sessions,1)
            self.assertGreaterEqual(f.guest_tls.forwarded_frames,5)
            self.assertGreaterEqual(f.gateway.verified_tls_sessions,1)
            self.assertGreaterEqual(f.peer.secure_sessions,1)

    def test_untrusted_server_certificate_refused_by_client(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.maximum_version=ssl.TLSVersion.TLSv1_2
            with socket.create_connection(("127.0.0.1",f.guest_tls.server_address[1]),timeout=5) as raw:
                with self.assertRaises(ssl.SSLError):
                    with ctx.wrap_socket(raw,server_hostname="localhost"):pass
            self.assertEqual(f.guest_tls.forwarded_frames,0)

    def test_plaintext_is_not_accepted_by_tls_ingress(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            with socket.create_connection(("127.0.0.1",f.guest_tls.server_address[1]),timeout=3) as raw:
                raw.settimeout(3)
                raw.sendall(b"hello plaintext")
            self.assertEqual(f.guest_tls.forwarded_frames,0)

if __name__=="__main__":unittest.main()
