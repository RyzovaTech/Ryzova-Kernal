# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.1: real 3-hop TLS1.2/9P/mTLS1.3 peer policy tests.

These prove host gateway client identity, not Ryzova guest client identity.
The native AMD64 QEMU job separately preserves Phase 7 guest TLS proof.
"""
import hashlib
from pathlib import Path
import socket
import ssl
import struct
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from ryzova.remote.native_bridge import BridgeDenied, read_frame
from ryzova.remote.p9 import MAX_FRAME, RERROR, RVERSION, ReadOnly9PClient, frame, unframe
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from ryzova.remote.phase8_9p_service import authorize_peer_request
from ryzova.remote.phase8_trust import PeerGrant, ResearchTrustPolicy, TrustDenied


def grant_policy(pin, *, enabled=True, allow_file=True, expires=None):
    grant = PeerGrant("gateway", pin, (
        int(time.time()) + 3600 if expires is None else expires),
        files=("probe",) if allow_file else ("other",))
    return ResearchTrustPolicy(peers=(grant,), enabled=enabled)


def native_session(f):
    cafile = str(Path(f._directory.name) / "server.pem")
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection(
        ("127.0.0.1", f.guest_tls.server_address[1]), timeout=5)
    raw.settimeout(5)
    try:
        secure = ctx.wrap_socket(raw, server_hostname="localhost")
    except Exception:
        raw.close()
        raise
    if secure.version() != "TLSv1.2":
        secure.close()
        raise AssertionError("wrong native guest-facing TLS protocol")
    fingerprint = hashlib.sha256(
        secure.getpeercert(binary_form=True)).hexdigest()
    if fingerprint != f.guest_cert_sha256:
        secure.close()
        raise AssertionError("guest server certificate mismatch")
    return secure


def read_probe(f):
    with native_session(f) as tls:
        def exchange(packet):
            tls.sendall(packet)
            return read_frame(tls)
        return ReadOnly9PClient(exchange).read_file("probe", max_total=4096)


class Authenticated9PServiceTests(unittest.TestCase):
    def test_actual_tls12_guest_ingress_and_mtls13_peer_read_sha256(self):
        payload = b"phase8-native-9p-public-fixture\n"
        with Ephemeral9PTLSFixture(
                payload, research_policy_factory=grant_policy) as f:
            response = read_probe(f)
            self.assertEqual(response, payload)
            self.assertEqual(hashlib.sha256(response).digest(),
                             hashlib.sha256(payload).digest())
            self.assertGreaterEqual(f.guest_tls.forwarded_frames, 5)
            self.assertGreaterEqual(f.gateway.verified_tls_sessions, 1)
            self.assertGreaterEqual(f.peer.secure_sessions, 1)
            self.assertGreaterEqual(f.peer.frames, 5)
            self.assertEqual(f.peer.policy_denials, 0)

    def test_untrusted_policy_blocks_all_file_data(self):
        for factory in (
            lambda pin: grant_policy(pin, enabled=False),
            lambda pin: grant_policy("0" * 64),
            lambda pin: grant_policy(pin, allow_file=False),
            lambda pin: grant_policy(pin, expires=int(time.time()) - 10),
            lambda pin: ResearchTrustPolicy(
                peers=(PeerGrant("another", pin, int(time.time()) + 60),),
                enabled=True),
            lambda pin: ResearchTrustPolicy(
                peers=(PeerGrant("gateway", pin, int(time.time()) + 60),),
                revoked_sha256=frozenset({pin}), enabled=True),
        ):
            with self.subTest(factory=factory):
                with Ephemeral9PTLSFixture(
                        b"public", research_policy_factory=factory) as f:
                    with self.assertRaises((BridgeDenied, OSError,
                                            ssl.SSLError)):
                        read_probe(f)
                    self.assertEqual(f.peer.frames, 0)
                    self.assertGreaterEqual(f.peer.policy_denials, 1)

    def test_revocation_applies_to_existing_and_new_connections(self):
        with Ephemeral9PTLSFixture(
                b"public", research_policy_factory=grant_policy) as f:
            with native_session(f) as tls:
                req = frame(100, 4, struct.pack("<I", MAX_FRAME)
                            + b"\x06\x009P2000")
                tls.sendall(req)
                kind, tag, _ = unframe(read_frame(tls))
                self.assertEqual((kind, tag), (RVERSION, 4))
                # Peer frame counter may lag downstream socket delivery.
                deadline = time.monotonic() + 2
                while f.peer.frames < 1 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertGreaterEqual(f.peer.frames, 1)
                original_frames = f.peer.frames
                old = f.peer.research_policy
                f.peer.research_policy = old.revoke_peer(
                    "gateway", new_generation=old.generation + 1)
                tls.sendall(frame(104, 5, struct.pack("<II", 1, 0xffffffff)
                                  + b"\x00\x00\x00\x00"))
                with self.assertRaises((BridgeDenied, OSError, ssl.SSLError)):
                    read_frame(tls)
                self.assertEqual(f.peer.frames, original_frames)
            with self.assertRaises((BridgeDenied, OSError, ssl.SSLError)):
                read_probe(f)
            self.assertGreaterEqual(f.peer.policy_denials, 2)

    def test_concurrent_fid_tables_remain_separate_under_mtls_policy(self):
        with Ephemeral9PTLSFixture(
                b"independent", research_policy_factory=grant_policy) as f:
            with ThreadPoolExecutor(max_workers=3) as workers:
                output = list(workers.map(lambda _: read_probe(f), range(3)))
            self.assertEqual(output, [b"independent"] * 3)
            self.assertGreaterEqual(f.peer.secure_sessions, 3)
            self.assertEqual(f.peer.policy_denials, 0)

    def test_write_denied_without_reaching_authorized_peer(self):
        with Ephemeral9PTLSFixture(
                b"public", research_policy_factory=grant_policy) as f:
            with native_session(f) as tls:
                tls.sendall(frame(118, 20, struct.pack("<IQI", 1, 0, 1)
                                  + b"X"))
                kind, tag, _ = unframe(read_frame(tls))
                self.assertEqual((kind, tag), (RERROR, 20))
            self.assertEqual(f.peer.frames, 0)
            self.assertEqual(f.gateway.forwarded_frames, 0)
            self.assertEqual(f.guest_tls.denied_writes, 1)

    def test_plain_boolean_tls_proof_cannot_bypass_socket_guard(self):
        policy = grant_policy("1" * 64)
        for fake in (None, True, object(), "TLSv1.3"):
            with self.subTest(fake=fake):
                with self.assertRaises(TrustDenied):
                    authorize_peer_request(policy, fake, "gateway")

    def test_9p_malformed_scope_is_rejected_before_data_release(self):
        with Ephemeral9PTLSFixture(
                b"public", research_policy_factory=grant_policy) as f:
            with native_session(f) as tls:
                # Start a real upstream TLS session and negotiate 9P version.
                tls.sendall(frame(100, 1, struct.pack("<I", MAX_FRAME)
                                  + b"\x06\x009P2000"))
                unframe(read_frame(tls))
                # A TREAD for an unknown fid is denied before processing.
                tls.sendall(frame(116, 2, struct.pack("<IQI", 987, 0, 64)))
                with self.assertRaises((BridgeDenied, OSError, ssl.SSLError)):
                    read_frame(tls)
            self.assertGreaterEqual(f.peer.policy_denials, 1)

    def test_gateway_disconnection_does_not_replay_or_corrupt_new_session(self):
        with Ephemeral9PTLSFixture(
                b"resilient", research_policy_factory=grant_policy) as f:
            self.assertEqual(read_probe(f), b"resilient")
            before = f.peer.frames
            original = f.gateway.upstream_port
            f.gateway.upstream_port = 0
            try:
                with self.assertRaises((BridgeDenied, OSError, ssl.SSLError)):
                    read_probe(f)
                self.assertEqual(f.peer.frames, before)
            finally:
                f.gateway.upstream_port = original
            self.assertEqual(read_probe(f), b"resilient")
            self.assertGreater(f.peer.frames, before)


if __name__ == "__main__":
    unittest.main()
