# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from compact_c3_remote import RESOURCE, payload, sha, transport_evidence
from ryzova.remote.native_bridge import bounded_io_timeout


class RemoteEvidenceTests(unittest.TestCase):
    def test_partition_requires_exit_evidence_empty_output_and_matching_resource(self):
        source = "a" * 40
        endpoint = SimpleNamespace(tls12_sessions=1)
        gateway = SimpleNamespace(verified_tls_sessions=1, forwarded_frames=8)
        route = SimpleNamespace(partitioned=True,
                                peers={node: dict(netns=f"net:[{i}]", address=f"10.0.0.{i}")
                                       for i, node in enumerate(("a", "b"), 1)},
                                endpoints={node: endpoint for node in ("a", "b")},
                                gateways={node: gateway for node in ("a", "b")},
                                pins={node: str(i)*64 for i, node in enumerate(("a", "b"), 1)})
        serial = ("C3_PARTITION_BEGIN\nC3_PRIMARY_LINK_DOWN\nC3_PRIMARY_READ_FAILED\n"
                  f"{sha(b'')} /tmp/c3-dead.out\n"
                  f"cat: can't open {RESOURCE}: mount rpc error: '{RESOURCE}'\n"
                  "C3_PARTITION_END\n").encode()
        self.assertTrue(transport_evidence(route, source, serial)["primary_link_failure"])
        for old, new in ((b"C3_PRIMARY_READ_FAILED", b"missing"),
                         (b"mount rpc error", b"permission denied"),
                         (sha(b"").encode(), sha(b"cached").encode()),
                         (RESOURCE.encode(), b"/n/wrong/probe")):
            with self.subTest(old=old):
                with self.assertRaises(ValueError):
                    transport_evidence(route, source, serial.replace(old, new))
        route.partitioned = False
        with self.assertRaises(ValueError):
            transport_evidence(route, source, serial)

    def test_distinct_payloads_bind_source_and_node(self):
        self.assertNotEqual(payload("a"*40, "a"), payload("a"*40, "b"))
        self.assertNotEqual(payload("a"*40), payload("b"*40))
        with self.assertRaises(ValueError):
            payload("a"*40, "untrusted-node")

    def test_timeout_remains_bounded(self):
        self.assertEqual(bounded_io_timeout(5), 5)
        self.assertEqual(bounded_io_timeout(25), 25)
        for value in (0, -1, 31, True, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    bounded_io_timeout(value)


if __name__ == "__main__":
    unittest.main()
