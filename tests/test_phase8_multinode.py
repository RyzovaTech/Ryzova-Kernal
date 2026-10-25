# SPDX-License-Identifier: AGPL-3.0-only
"""Real separate TCP listeners with TLS1.3 mutual authentication and 9P/CPU.

These local TCP tests do not substitute for isolated-network CI evidence.
"""
from dataclasses import replace
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from ryzova.remote.phase8_cluster import (
    ResourceRegistry, ResourceDenied, UnifiedCoordinator, Workload)
from ryzova.remote.phase8_multinode import (
    NodeService, RemoteNode, TransportDenied, client_context, digest_file,
    recv_message, send_message, server_context)
from ryzova.remote.p9 import frame

class MultiNodeTLSHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="ryzova-8-2-tls-")
        cls.root = Path(cls.tmp.name)
        for name in ("controller", "node-a", "node-b", "other-client"):
            path = cls.root / name
            subject = "localhost" if name in ("controller", "other-client") else name
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-sha256", "-days", "1", "-subj", "/CN=" + subject,
                "-addext", "subjectAltName=DNS:" + subject,
                "-keyout", str(path.with_suffix(".key")),
                "-out", str(path.with_suffix(".pem"))],
                capture_output=True, check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def files(cls, name):
        return str(cls.root / (name + ".pem")), str(cls.root / (name + ".key"))

    def setUp(self):
        controller_cert, controller_key = self.files("controller")
        self.servers, self.threads, self.clients = [], [], {}
        for name in ("node-a", "node-b"):
            cert, key = self.files(name)
            service = NodeService(
                ("127.0.0.1", 0),
                context=server_context(cert, key, controller_cert),
                controller_pin=digest_file(controller_cert),
                node_id=name, node_pin=digest_file(cert),
                payload=("fixture " + name).encode("ascii"))
            thread = threading.Thread(target=service.serve_forever,
                                      kwargs={"poll_interval":0.05},
                                      daemon=True)
            thread.start()
            self.servers.append(service)
            self.threads.append(thread)
            self.clients[name] = RemoteNode(
                name, ("127.0.0.1", service.server_address[1]), name,
                digest_file(cert),
                client_context(controller_cert, controller_key, cert))
        self.registry = ResourceRegistry({
            name: client.expected_pin for name, client in self.clients.items()},
            enabled=True)

    def tearDown(self):
        for server in self.servers:
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def discover(self):
        now = int(time.time())
        for name in ("node-a", "node-b"):
            offer = self.clients[name].discover(self.registry, now=now)
            self.assertEqual(offer.node_id, name)
            self.assertEqual(offer.roles, frozenset({"compute", "storage"}))
        return now

    def test_real_two_independent_tls_services_9p_integrity(self):
        self.discover()
        for name, client in self.clients.items():
            expected = ("fixture " + name).encode()
            payload = client.read_probe()
            self.assertEqual(payload, expected)
            self.assertEqual(hashlib.sha256(payload).hexdigest(),
                             hashlib.sha256(expected).hexdigest())
            self.assertEqual(client.compute("sha256", payload),
                             hashlib.sha256(payload).hexdigest())

    def test_discovery_is_bound_to_verified_certificate_not_offer_string(self):
        self.discover()
        service = self.servers[0]
        original = service.offer
        service.offer = replace(original, node_id="forged-node")
        try:
            with self.assertRaises(TransportDenied):
                self.clients["node-a"].discover(
                    ResourceRegistry({"node-a": original.cert_pin}, enabled=True),
                    now=int(time.time()))
        finally:
            service.offer = original

    def test_wrong_server_pin_and_wrong_client_certificate_fail_closed(self):
        valid = self.clients["node-a"]
        mismatch = RemoteNode("node-a", valid.address, valid.tls_name,
                              "f" * 64, valid.context)
        with self.assertRaises(TransportDenied):
            mismatch.read_probe()
        node_cert, _ = self.files("node-a")
        other_cert, other_key = self.files("other-client")
        incorrect = RemoteNode("node-a", valid.address, valid.tls_name,
                               valid.expected_pin,
                               client_context(other_cert, other_key, node_cert))
        with self.assertRaises((ssl.SSLError, TransportDenied, OSError)):
            incorrect.read_probe()

    def test_lease_expired_and_wrong_declared_generation(self):
        service = self.servers[0]
        original = service.offer
        service.offer = replace(original, lease_until=int(time.time()) - 1)
        try:
            with self.assertRaises(ResourceDenied):
                self.clients["node-a"].discover(
                    self.registry, now=int(time.time()))
        finally:
            service.offer = original
        self.clients["node-a"].discover(self.registry, now=int(time.time()))
        with self.assertRaises(ResourceDenied):
            self.clients["node-a"].discover(self.registry, now=int(time.time()))

    def test_real_multi_node_scheduler_distributes_eligible_jobs(self):
        now = self.discover()
        coordinator = UnifiedCoordinator(
            self.registry, {key: client.compute
                            for key, client in self.clients.items()}, enabled=True)
        task = Workload(kind="sha256", payload=b"research-public",
                        architecture="amd64", allow_remote=True)
        placements = [coordinator.submit(task, now=now).node_id
                      for _ in range(6)]
        self.assertEqual(placements, ["node-a", "node-b"] * 3)

    def test_isolated_network_failure_falls_back_to_second_node(self):
        now = self.discover()
        dead = self.servers[0]
        dead.shutdown()
        dead.server_close()
        self.servers[0] = None
        coordinator = UnifiedCoordinator(
            self.registry, {key: client.compute
                            for key, client in self.clients.items()}, enabled=True)
        r = coordinator.submit(Workload("byte_count", b"safe", allow_remote=True),
                               now=now)
        self.assertEqual((r.node_id, r.result, r.attempts),
                         ("node-b", 4, 2))
        self.assertEqual([offer.node_id for offer in self.registry.offers(now)],
                         ["node-b"])

    def test_public_wildcard_node_listener_and_unverified_tls_context_denied(self):
        controller, _ = self.files("controller")
        cert, key = self.files("node-a")
        with self.assertRaises(ValueError):
            NodeService(
                ("0.0.0.0", 0),
                context=server_context(cert, key, controller),
                controller_pin=digest_file(controller),
                node_id="node-a", node_pin=digest_file(cert))
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        valid = self.clients["node-a"]
        with self.assertRaises(ValueError):
            RemoteNode("node-a", valid.address, "node-a",
                       valid.expected_pin, unverified)

    def test_unknown_9p_write_is_refused_on_authenticated_channel(self):
        with self.clients["node-a"].connect() as tls:
            send_message(tls, {"op":"9p",
                               "frame":base64.b64encode(
                                   frame(118, 9, struct.pack("<IQI",1,0,1) + b"X")
                               ).decode("ascii")})
            with self.assertRaises((TransportDenied, OSError, ssl.SSLError)):
                recv_message(tls)

    def test_untrusted_commands_and_large_data_rejected(self):
        with self.clients["node-a"].connect() as tls:
            send_message(tls, {"op":"compute", "kind":"shell",
                               "data":base64.b64encode(b"whoami").decode()})
            with self.assertRaises((TransportDenied, OSError, ssl.SSLError)):
                recv_message(tls)
        with self.assertRaises(ValueError):
            self.clients["node-a"].compute("shell", b"whoami")
        with self.assertRaises(ValueError):
            self.clients["node-a"].compute("sha256", b"x" * 4097)

    def test_concurrent_tls_sessions_have_independent_9p_fids(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            chunks = list(pool.map(
                lambda _: self.clients["node-b"].read_probe(), range(4)))
        self.assertEqual(chunks, [b"fixture node-b"] * 4)


if __name__ == "__main__":
    unittest.main()
