# SPDX-License-Identifier: AGPL-3.0-only
"""Real socket TLS 1.3 9P gateway, negative cert and read-only tests."""
import hashlib
import socket
import struct
import unittest

from ryzova.remote.native_bridge import (
    Local9PTLSGateway, BridgeDenied, read_frame)
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from ryzova.remote.p9 import ReadOnly9PClient, frame, unframe, RERROR
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

if __name__=="__main__":
    unittest.main()
