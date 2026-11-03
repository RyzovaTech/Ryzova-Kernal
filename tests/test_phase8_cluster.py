# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.2 Option B: bounded, opt-in logical-node scheduling research tests."""
from dataclasses import replace
import hashlib
import unittest

from ryzova.remote.phase8_cluster import (
    NodeOffer, ResourceRegistry, ResourceDenied,
    UnifiedCoordinator, Workload, public_pure_handler,
)

NOW = 1000
PIN_A = "a" * 64
PIN_B = "b" * 64
PIN_C = "c" * 64


def offer(name, pin, **overrides):
    base = dict(node_id=name, cert_pin=pin, roles=frozenset({"compute"}),
                architectures=frozenset({"amd64"}), slots=4, busy=0,
                latency_ms=10, lease_until=NOW + 120,
                generation=1, local=False, max_payload=4096)
    return NodeOffer(**(base | overrides))


def job(**updates):
    return Workload(**(dict(kind="sha256", payload=b"public-workload",
                           architecture="amd64", allow_remote=True) | updates))


class UnifiedResourceTests(unittest.TestCase):
    def registry(self):
        return ResourceRegistry(
            {"remote-a": PIN_A, "remote-b": PIN_B, "local-a": PIN_C},
            enabled=True)

    def admit(self, registry, node):
        registry.admit(node, presented_fingerprint=node.cert_pin, now=NOW)

    def test_disabled_registry_and_scheduler_are_fail_closed(self):
        n = offer("remote-a", PIN_A)
        with self.assertRaises(ResourceDenied):
            ResourceRegistry({"remote-a": PIN_A}).admit(
                n, presented_fingerprint=PIN_A, now=NOW)
        registry = self.registry()
        self.admit(registry, n)
        with self.assertRaises(ResourceDenied):
            UnifiedCoordinator(registry, {"remote-a": public_pure_handler}).submit(
                job(), now=NOW)

    def test_automatic_low_load_selection_across_logical_nodes(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A, slots=8, busy=0,
                                   latency_ms=40))
        self.admit(registry, offer("remote-b", PIN_B, slots=4, busy=2,
                                   latency_ms=5))
        self.admit(registry, offer("local-a", PIN_C, slots=2, busy=1,
                                   latency_ms=0, local=True))
        coordinator = UnifiedCoordinator(
            registry, dict.fromkeys(("remote-a", "remote-b", "local-a"),
                                    public_pure_handler), enabled=True)
        receipt = coordinator.submit(job(), now=NOW)
        self.assertEqual(receipt.node_id, "remote-a")
        self.assertEqual(receipt.operation, "sha256")
        self.assertEqual(receipt.attempts, 1)
        self.assertEqual(receipt.result,
                         hashlib.sha256(b"public-workload").hexdigest())
        self.assertEqual(registry.offers(NOW)[0].namespace,
                         "/cluster/nodes/remote-a")

    def test_successive_jobs_are_distributed_across_allowed_nodes(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A, slots=4,
                                   latency_ms=1))
        self.admit(registry, offer("remote-b", PIN_B, slots=4,
                                   latency_ms=2))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler,
                       "remote-b": public_pure_handler}, enabled=True)
        choices = [coordinator.submit(job(), now=NOW).node_id
                   for _ in range(6)]
        self.assertEqual(choices, ["remote-a", "remote-b"] * 3)

    def test_remote_requires_explicit_workload_opt_in(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler}, enabled=True)
        with self.assertRaises(ResourceDenied):
            coordinator.submit(job(allow_remote=False), now=NOW)
        self.assertEqual(coordinator.submit(job(), now=NOW).node_id, "remote-a")

    def test_local_fallback_after_remote_adapter_failure(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A, latency_ms=1))
        self.admit(registry, offer("local-a", PIN_C, local=True,
                                   latency_ms=80))
        seen = []
        def bad(op, payload):
            seen.append(op)
            raise ConnectionError("test-only node unavailable")
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": bad, "local-a": public_pure_handler},
            enabled=True)
        receipt = coordinator.submit(job(), now=NOW)
        self.assertEqual(receipt.node_id, "local-a")
        self.assertEqual(receipt.attempts, 2)
        self.assertEqual(seen, ["sha256"])
        self.assertEqual([n.node_id for n in registry.offers(NOW)], ["local-a"])
        self.assertEqual(coordinator.submit(job(), now=NOW).node_id, "local-a")

    def test_bad_result_is_quarantined_not_returned(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": lambda kind, data: "evil"}, enabled=True)
        with self.assertRaises(ResourceDenied):
            coordinator.submit(job(), now=NOW)
        self.assertEqual(registry.offers(NOW), ())

    def test_node_lease_expiry_fails_closed(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler}, enabled=True)
        self.assertEqual(coordinator.submit(job(), now=NOW).node_id, "remote-a")
        with self.assertRaises(ResourceDenied):
            coordinator.submit(job(), now=NOW + 120)

    def test_architecture_isolation(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A,
                                   architectures=frozenset({"arm64"})))
        self.admit(registry, offer("remote-b", PIN_B,
                                   architectures=frozenset({"amd64"})))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler,
                       "remote-b": public_pure_handler}, enabled=True)
        self.assertEqual(coordinator.submit(job(), now=NOW).node_id, "remote-b")
        self.assertEqual(coordinator.submit(
            job(architecture="arm64"), now=NOW).node_id, "remote-a")

    def test_storage_gpu_device_offers_are_discoverable_not_executed(self):
        registry = self.registry()
        roles = frozenset({"storage", "gpu", "device", "cache"})
        self.admit(registry, offer("remote-a", PIN_A, roles=roles))
        self.assertEqual(registry.offers(NOW)[0].roles, roles)
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler}, enabled=True)
        with self.assertRaises(ResourceDenied):
            coordinator.submit(job(), now=NOW)

    def test_unified_namespace_index_displays_resource_roles_not_mounts(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A,
                                   roles=frozenset({"compute", "storage",
                                                    "gpu", "cache", "network"}),
                                   architectures=frozenset({"amd64", "arm64"})))
        self.admit(registry, offer("remote-b", PIN_B,
                                   roles=frozenset({"device"})))
        names = registry.namespace_index(NOW)
        self.assertEqual(names, tuple(sorted((
            "/cluster/nodes/remote-a", "/cluster/nodes/remote-b",
            "/cluster/compute/amd64/remote-a",
            "/cluster/compute/arm64/remote-a",
            "/cluster/storage/remote-a", "/cluster/gpu/remote-a",
            "/cluster/cache/remote-a", "/cluster/network/remote-a",
            "/cluster/devices/remote-b",
        ))))
        self.assertNotIn("/cluster/storage/remote-b", names)
        self.assertEqual(registry.namespace_index(NOW + 120), ())

    def test_quota_and_full_capacity(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A, slots=1, busy=1))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler}, enabled=True)
        with self.assertRaises(ResourceDenied):
            coordinator.submit(job(), now=NOW)
        fresh = self.registry()
        self.admit(fresh, offer("remote-a", PIN_A, max_payload=2))
        other = UnifiedCoordinator(
            fresh, {"remote-a": public_pure_handler}, enabled=True)
        with self.assertRaises(ResourceDenied):
            other.submit(job(), now=NOW)

    def test_stale_generation_pin_and_impersonation_rejected(self):
        registry = self.registry()
        n = offer("remote-a", PIN_A)
        for supplied in (PIN_B, "Z" * 64, PIN_A[:-1]):
            with self.assertRaises(ResourceDenied):
                registry.admit(n, presented_fingerprint=supplied, now=NOW)
        with self.assertRaises(ResourceDenied):
            registry.admit(offer("unknown", PIN_B),
                           presented_fingerprint=PIN_B, now=NOW)
        self.admit(registry, n)
        with self.assertRaises(ResourceDenied):
            self.admit(registry, n)
        self.admit(registry, replace(n, generation=2, busy=1))
        with self.assertRaises(ResourceDenied):
            self.admit(registry, replace(n, generation=1))
        registry.quarantine("remote-a")
        with self.assertRaises(ResourceDenied):
            self.admit(registry, replace(n, generation=3))

    def test_deterministic_tie_break_and_byte_count(self):
        registry = self.registry()
        self.admit(registry, offer("remote-b", PIN_B, latency_ms=20))
        self.admit(registry, offer("remote-a", PIN_A, latency_ms=20))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler,
                       "remote-b": public_pure_handler}, enabled=True)
        result = coordinator.submit(job(kind="byte_count"), now=NOW)
        self.assertEqual((result.node_id, result.result), ("remote-a", 15))

    def test_slot_reservation_prevents_recursive_double_booking(self):
        registry = self.registry()
        self.admit(registry, offer("local-a", PIN_C, slots=1, local=True))
        coordinator = None
        def handler(kind, data):
            with self.assertRaises(ResourceDenied):
                coordinator.submit(job(allow_remote=False), now=NOW)
            return public_pure_handler(kind, data)
        coordinator = UnifiedCoordinator(registry, {"local-a": handler},
                                         enabled=True)
        self.assertEqual(coordinator.submit(
            job(allow_remote=False), now=NOW).node_id, "local-a")

    def test_no_unrestricted_program_execution_or_secrets(self):
        for kwargs in (dict(kind="shell"), dict(kind="python"),
                       dict(payload=b"x" * 4097), dict(payload=b""),
                       dict(architecture="mips"), dict(allow_remote=1)):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                job(**kwargs)
        with self.assertRaises(ValueError):
            offer("remote-a", PIN_A, roles=frozenset({"root-shell"}))
        with self.assertRaises(ValueError):
            offer("remote-a", PIN_A, slots=0)
        with self.assertRaises(ValueError):
            offer("../other", PIN_A)
        with self.assertRaises(ValueError):
            offer("remote-a", PIN_A, cert_pin="0" * 63)

    def test_invalid_retry_count_denied(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": public_pure_handler}, enabled=True)
        for attempts in (-1, 0, 3, False, 1.5):
            with self.assertRaises(ValueError):
                coordinator.submit(job(), now=NOW, max_attempts=attempts)

    def test_byte_count_bool_response_is_rejected(self):
        registry = self.registry()
        self.admit(registry, offer("remote-a", PIN_A))
        coordinator = UnifiedCoordinator(
            registry, {"remote-a": lambda *_: True}, enabled=True)
        with self.assertRaises(ResourceDenied):
            coordinator.submit(job(kind="byte_count"), now=NOW)


if __name__ == "__main__":
    unittest.main()
