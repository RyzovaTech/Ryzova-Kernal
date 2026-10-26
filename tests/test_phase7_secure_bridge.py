# SPDX-License-Identifier: AGPL-3.0-only
"""Real socket TLS 1.3 9P gateway, negative cert and read-only tests."""
import hashlib
import socket
import struct
import unittest
import threading
import time
from contextlib import contextmanager
from unittest.mock import patch

from ryzova.remote.native_bridge import (
    Local9PTLSGateway, SecureReadOnly9PPeer, BridgeDenied, read_frame)
from ryzova.remote.native9p import Native9PTCPServer
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from ryzova.remote.p9 import (ReadOnly9PClient, frame, unframe, RERROR,
                              TVERSION, RVERSION)
from ryzova.remote.cache import RemotePageCache


def connected_reader(port):
    s=socket.create_connection(("127.0.0.1",port),timeout=4)
    s.settimeout(4)
    def exchange(raw):
        s.sendall(raw)
        return read_frame(s)
    return s, ReadOnly9PClient(exchange)


class Phase7GatewayTests(unittest.TestCase):
    def test_actual_9p_file_through_pinned_mutual_tls(self):
        data=b"Ryzova Phase7 from real peer\n"
        with Ephemeral9PTLSFixture(data) as f:
            s,client=connected_reader(f.gateway.server_address[1])
            with s:
                self.assertEqual(client.read_file("probe"),data)
            self.assertGreaterEqual(f.gateway.forwarded_frames,5)
            self.assertGreaterEqual(f.peer.frames,5)
            self.assertGreaterEqual(f.gateway.verified_tls_sessions,1)
            self.assertGreaterEqual(f.peer.secure_sessions,1)

    def test_isolated_multi_client_fid_tables(self):
        with Ephemeral9PTLSFixture(b"public-data") as f:
            for _ in range(3):
                s,client=connected_reader(f.gateway.server_address[1])
                with s:self.assertEqual(client.read_file("probe"),b"public-data")
            self.assertGreaterEqual(f.gateway.verified_tls_sessions,3)

    def test_denied_write_not_forwarded_upstream(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            s=socket.create_connection(("127.0.0.1",f.gateway.server_address[1]),timeout=4)
            s.settimeout(4)
            with s:
                for tag,kind in ((9,118),(10,114),(11,126)):
                    s.sendall(frame(kind,tag,struct.pack("<IQI",1,0,1)+b"X"))
                    answer,reply_tag,_=unframe(read_frame(s))
                    self.assertEqual((answer,reply_tag),(RERROR,tag))
                    # The denial counter must precede a delivered RERROR:
                    # do not rely on a polling/sleep workaround.
                    self.assertEqual(f.gateway.denied_writes,tag-8)
            self.assertEqual(f.peer.frames,0)
            self.assertEqual(f.gateway.denied_writes,3)

    def test_wrong_pin_does_not_serve_remote_content(self):
        with Ephemeral9PTLSFixture(b"top-public") as f:
            f.gateway.server_pin="0"*64
            s,client=connected_reader(f.gateway.server_address[1])
            with s, self.assertRaises((EOFError,OSError,BridgeDenied)):
                client.read_file("probe")
            self.assertEqual(f.gateway.forwarded_frames,0)

    def test_peer_disconnect_does_not_fall_back_to_plaintext(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            peer=f.peer
            peer.shutdown();peer.server_close()
            s,client=connected_reader(f.gateway.server_address[1])
            with s, self.assertRaises((EOFError,OSError,BridgeDenied)):
                client.read_file("probe")
            self.assertEqual(f.gateway.forwarded_frames,0)

    def test_pinned_cache_over_real_9p_tls_gateway(self):
        payload=b"Z"*4096
        with Ephemeral9PTLSFixture(payload) as f:
            s,client=connected_reader(f.gateway.server_address[1])
            with s:
                cache=RemotePageCache(capacity_pages=2)
                digest=hashlib.sha256(payload).hexdigest()
                self.assertEqual(cache.get("probe",digest,client.read_file),payload)
                self.assertEqual(cache.resident_bytes,4096)
                self.assertEqual(cache.get("probe",digest,lambda _:self.fail("must hit cache")),payload)

    def test_reject_oversized_9p_frame_length(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            with socket.create_connection(("127.0.0.1",f.gateway.server_address[1]),timeout=4) as s:
                s.sendall(struct.pack("<I",100000000))
            self.assertEqual(f.gateway.forwarded_frames,0)

    def test_fixture_cleanup_clears_private_certificates(self):
        f=Ephemeral9PTLSFixture(b"public").start()
        location=f._directory.name
        f.close()
        from pathlib import Path
        self.assertFalse(Path(location).exists())



class ListenerLimitTests(unittest.TestCase):
    @staticmethod
    def wait_for(predicate):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        raise AssertionError("listener state did not converge")

    @contextmanager
    def running(self, listener):
        thread = threading.Thread(
            target=lambda: listener.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        try:
            yield listener
        finally:
            listener.shutdown()
            listener.server_close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def factories(self, fixture):
        return (
            ("tcp", lambda **kw: Native9PTCPServer({"probe": b"x"}, port=0, **kw)),
            ("gateway", lambda **kw: Local9PTLSGateway(
                fixture.gateway.context, fixture.gateway.server_pin,
                fixture.peer.server_address[1], port=0, **kw)),
            ("peer", lambda **kw: SecureReadOnly9PPeer(
                {"probe": b"x"}, fixture.peer.context, fixture.peer.client_pin, **kw)),
        )

    def connect(self, listener, kind, fixture):
        raw = socket.create_connection(listener.server_address, timeout=3)
        raw.settimeout(3)
        if kind != "peer":
            return raw
        try:
            return fixture.gateway.context.wrap_socket(raw, server_hostname="localhost")
        except BaseException:
            raw.close()
            raise

    def test_direct_listeners_bound_admission_and_recover_slots(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            for kind, factory in self.factories(f):
                with self.subTest(kind=kind), self.running(factory(max_sessions=1)) as srv:
                    # An idle raw peer socket holds a TLS handshake slot too.
                    with socket.create_connection(srv.server_address, timeout=3) as held:
                        self.wait_for(lambda: srv.active_sessions == 1)
                        with socket.create_connection(srv.server_address, timeout=3) as excess:
                            excess.settimeout(3)
                            self.assertEqual(excess.recv(1), b"")
                        self.wait_for(lambda: srv.rejected_connections == 1)
                        self.assertEqual(srv.peak_sessions, 1)
                    self.wait_for(lambda: srv.active_sessions == 0)
                    # A failed handshake/disconnect must not leak its slot.
                    with self.connect(srv, kind, f) as recovered:
                        recovered.sendall(frame(TVERSION, 1,
                            struct.pack("<I", 8192) + b"\x06\x009P2000"))
                        self.assertEqual(unframe(read_frame(recovered))[0], RVERSION)
                    self.wait_for(lambda: srv.active_sessions == 0)

    def test_direct_listeners_close_after_frame_quota(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            for kind, factory in self.factories(f):
                with self.subTest(kind=kind), self.running(
                        factory(max_frames_per_session=2)) as srv:
                    with self.connect(srv, kind, f) as client:
                        for tag in (1, 2):
                            client.sendall(frame(TVERSION, tag,
                                struct.pack("<I", 8192) + b"\x06\x009P2000"))
                            self.assertEqual(unframe(read_frame(client))[0], RVERSION)
                        self.assertEqual(client.recv(1), b"")
                    self.wait_for(lambda: srv.active_sessions == 0)
                    self.assertEqual(srv.frame_quota_closes, 1)

    def test_gateway_denials_also_consume_frame_quota(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            factory = dict(self.factories(f))["gateway"]
            with self.running(factory(max_frames_per_session=2)) as srv:
                with self.connect(srv, "gateway", f) as client:
                    for tag in (1, 2):
                        client.sendall(frame(118, tag, b""))
                        self.assertEqual(unframe(read_frame(client))[0], RERROR)
                    self.assertEqual(client.recv(1), b"")
                self.wait_for(lambda: srv.active_sessions == 0)
                self.assertEqual(srv.frame_quota_closes, 1)
                self.assertEqual(srv.forwarded_frames, 0)

    def test_thread_start_failure_releases_admission_slot(self):
        srv = Native9PTCPServer({"probe": b"x"}, port=0, max_sessions=1)
        try:
            with socket.socket() as request:
                self.assertTrue(srv.verify_request(request, ("127.0.0.1", 1)))
                with patch.object(threading.Thread, "start", side_effect=RuntimeError):
                    with self.assertRaises(RuntimeError):
                        srv.process_request(request, ("127.0.0.1", 1))
                self.assertEqual(srv.active_sessions, 0)
        finally:
            srv.server_close()

    def test_invalid_limits_rejected_before_listening(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            for kind, factory in self.factories(f):
                for keyword, maximum in (("max_sessions", 32),
                                         ("max_frames_per_session", 4096)):
                    for value in (0, -1, maximum + 1, True, None):
                        with self.subTest(kind=kind, keyword=keyword, value=value):
                            with self.assertRaises(ValueError):
                                factory(**{keyword: value})


if __name__ == "__main__":
    unittest.main()

