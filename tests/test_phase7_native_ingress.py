# SPDX-License-Identifier: AGPL-3.0-only
"""Real TLS1.2 guest-facing 9P socket test with upstream mutual TLS1.3."""
import hashlib
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from ryzova.remote.native_bridge import BridgeDenied, read_frame
from ryzova.remote.p9 import MAX_FRAME, RERROR, RVERSION, ReadOnly9PClient, frame, unframe

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


class NativeIngressFailureAndQuotaTests(unittest.TestCase):
    @staticmethod
    def secure_connection(f):
        trusted = str(Path(f._directory.name) / "server.pem")
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=trusted)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection(
            ("127.0.0.1", f.guest_tls.server_address[1]), timeout=5)
        raw.settimeout(5)
        return ctx.wrap_socket(raw, server_hostname="localhost")

    @classmethod
    def remote_read(cls, f):
        with cls.secure_connection(f) as secure:
            def exchange(req):
                secure.sendall(req)
                return read_frame(secure)
            return ReadOnly9PClient(exchange).read_file("probe")

    def test_write_and_unknown_operations_do_not_reach_peer(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            with self.secure_connection(f) as secure:
                for tag, kind in ((7, 118), (8, 122), (9, 126), (10, 199)):
                    secure.sendall(frame(kind, tag))
                    answer, reply_tag, _ = unframe(read_frame(secure))
                    self.assertEqual((answer, reply_tag), (RERROR, tag))
            self.assertEqual(f.guest_tls.denied_writes, 4)
            self.assertEqual(f.guest_tls.forwarded_frames, 0)
            self.assertEqual(f.gateway.forwarded_frames, 0)
            self.assertEqual(f.peer.frames, 0)

    def test_malformed_tls_protected_9p_length_does_not_forward(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            with self.secure_connection(f) as secure:
                secure.sendall(struct.pack("<I", MAX_FRAME + 1))
                with self.assertRaises((BridgeDenied, OSError)):
                    read_frame(secure)
            self.assertEqual(f.guest_tls.forwarded_frames, 0)
            self.assertEqual(f.gateway.forwarded_frames, 0)
            self.assertEqual(self.remote_read(f), b"public")

    def test_tls13_only_client_cannot_downgrade_or_forward(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=str(Path(f._directory.name) / "server.pem"))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(
                    ("127.0.0.1", f.guest_tls.server_address[1]), timeout=5) as raw:
                raw.settimeout(5)
                with self.assertRaises(ssl.SSLError):
                    ctx.wrap_socket(raw, server_hostname="localhost")
            self.assertEqual(f.guest_tls.tls12_sessions, 0)
            self.assertEqual(f.guest_tls.forwarded_frames, 0)

    def test_session_capacity_rejects_without_spawning_unbounded_handlers(self):
        with Ephemeral9PTLSFixture(
                b"public", max_guest_sessions=1) as f:
            with self.secure_connection(f) as first:
                self.assertEqual(f.guest_tls.active_sessions, 1)
                with self.assertRaises(OSError):
                    self.secure_connection(f)
                self.assertEqual(f.guest_tls.rejected_connections, 1)
                self.assertLessEqual(f.guest_tls.peak_sessions, 1)
            deadline = time.monotonic() + 3
            while f.guest_tls.active_sessions and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(f.guest_tls.active_sessions, 0)
            self.assertEqual(self.remote_read(f), b"public")

    def test_frame_quota_closes_session_and_releases_capacity(self):
        version = struct.pack("<I", MAX_FRAME) + b"\x06\x009P2000"
        with Ephemeral9PTLSFixture(
                b"public", max_guest_frames=2) as f:
            with self.secure_connection(f) as secure:
                for tag in (1, 2):
                    secure.sendall(frame(100, tag, version))
                    answer, reply_tag, _ = unframe(read_frame(secure))
                    self.assertEqual((answer, reply_tag), (RVERSION, tag))
                with self.assertRaises((BridgeDenied, OSError)):
                    read_frame(secure)
            self.assertEqual(f.guest_tls.frame_quota_closes, 1)
            with self.secure_connection(f) as secure:
                secure.sendall(frame(100, 3, version))
                answer, reply_tag, _ = unframe(read_frame(secure))
                self.assertEqual((answer, reply_tag), (RVERSION, 3))
            self.assertLessEqual(f.guest_tls.peak_sessions, 2)

    def test_upstream_outage_fails_closed_and_fresh_session_recovers(self):
        with Ephemeral9PTLSFixture(b"recovery-proof") as f:
            self.assertEqual(self.remote_read(f), b"recovery-proof")
            forwarded = f.gateway.forwarded_frames
            original_port = f.gateway.upstream_port
            f.gateway.upstream_port = 0  # Simulate an unreachable TLS peer.
            try:
                with self.assertRaises((BridgeDenied, OSError)):
                    self.remote_read(f)
                self.assertEqual(f.gateway.forwarded_frames, forwarded)
            finally:
                f.gateway.upstream_port = original_port
            # No replay, implicit retry, or plaintext fallback; caller creates
            # a new TLS session and a fresh 9P fid namespace.
            self.assertEqual(self.remote_read(f), b"recovery-proof")
            self.assertGreater(f.gateway.forwarded_frames, forwarded)

    def test_concurrent_tls_clients_keep_independent_9p_fids(self):
        with Ephemeral9PTLSFixture(b"parallel") as f:
            with ThreadPoolExecutor(max_workers=3) as pool:
                result = list(pool.map(lambda _: self.remote_read(f), range(3)))
            self.assertEqual(result, [b"parallel"] * 3)
            self.assertGreaterEqual(f.guest_tls.tls12_sessions, 3)
            self.assertGreaterEqual(f.peer.secure_sessions, 3)

    def test_reject_invalid_resource_limit_configuration(self):
        with self.assertRaises(ValueError):
            with Ephemeral9PTLSFixture(b"public", max_guest_sessions=0):
                pass
        with self.assertRaises(ValueError):
            with Ephemeral9PTLSFixture(b"public", max_guest_frames=0):
                pass

if __name__=="__main__":unittest.main()
