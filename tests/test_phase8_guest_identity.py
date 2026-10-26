# SPDX-License-Identifier: AGPL-3.0-only
"""Actual TLS client-certificate verification and native evidence rejection."""
import hashlib
from pathlib import Path
import socket
import ssl
import sys
import unittest

from ryzova.remote.native_bridge import read_frame, BridgeDenied
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from ryzova.remote.p9 import ReadOnly9PClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from phase8_guest_identity import commands, inspect
from phase6_native_9p import payload_for_commit


class GuestIdentityTests(unittest.TestCase):
    def read(self, fixture, certificate=True):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cafile=str(Path(fixture._directory.name) / "server.pem"))
        if certificate:
            ctx.load_cert_chain(str(fixture.guest_client_cert), str(fixture.guest_client_key))
        with socket.create_connection(fixture.authenticated_guest_tls.server_address,
                                      timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                def exchange(packet):
                    tls.sendall(packet)
                    return read_frame(tls)
                return ReadOnly9PClient(exchange).read_file("probe")

    def test_live_client_certificate_required_before_any_9p_forward(self):
        with Ephemeral9PTLSFixture(b"public", enable_guest_identity=True) as f:
            with self.assertRaises((OSError, ssl.SSLError, BridgeDenied, EOFError)):
                self.read(f, certificate=False)
            self.assertEqual(f.authenticated_guest_tls.forwarded_frames, 0)
            self.assertEqual(f.authenticated_guest_tls.authenticated_guest_sessions, 0)
            self.assertEqual(self.read(f), b"public")
            self.assertEqual(f.authenticated_guest_tls.authenticated_guest_sessions, 1)

    def test_valid_tls_certificate_with_wrong_pin_rejected(self):
        with Ephemeral9PTLSFixture(b"public", enable_guest_identity=True) as f:
            f.authenticated_guest_tls.guest_client_pin = "0" * 64
            with self.assertRaises((OSError, ssl.SSLError, BridgeDenied, EOFError)):
                self.read(f)
            self.assertEqual(f.authenticated_guest_tls.forwarded_frames, 0)
            self.assertEqual(f.authenticated_guest_tls.authenticated_guest_sessions, 0)

    def test_guest_identity_default_is_not_claimed(self):
        with Ephemeral9PTLSFixture(b"public") as f:
            self.assertIsNone(f.authenticated_guest_tls)
            self.assertEqual(f.guest_tls.authenticated_guest_sessions, 0)
            self.assertIsNone(f.guest_tls.guest_identity)

    def test_echoed_markers_and_host_only_counts_do_not_prove_native_identity(self):
        sha = "a" * 40
        serial = "\r\n".join(commands()).encode()
        self.assertFalse(inspect(serial, sha, "1" * 64, 1, 8)["passed"])
        payload = payload_for_commit(sha)
        serial = (b"RYZOVA_GUEST_IDENTITY_READ_BEGIN\n" + payload
            + b"RYZOVA_GUEST_IDENTITY_READ_END\n"
            + hashlib.sha256(payload).hexdigest().encode() + b" /n/ryzova8/probe\n"
            + b"".join(f"RYZOVA_RUNTIME_STAGE_{i}\n".encode() for i in range(20, 26))
            + b"RYZOVA_GUEST_IDENTITY_DONE\n")
        self.assertTrue(inspect(serial, sha, "1" * 64, 1, 8)["passed"])
        self.assertFalse(inspect(serial, sha, "1" * 64, 0, 8)["passed"])
        self.assertFalse(inspect(serial, sha, "1" * 64, 1, 0)["passed"])
        self.assertFalse(inspect(serial, "b" * 40, "1" * 64, 1, 8)["passed"])

    def test_private_key_contents_never_embedded_in_commands(self):
        for command in commands():
            self.assertNotIn("BEGIN PRIVATE KEY", command)
            self.assertNotIn("!dk=", command)


if __name__ == "__main__":
    unittest.main()
