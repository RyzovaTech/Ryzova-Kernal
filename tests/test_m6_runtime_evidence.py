# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic evidence contract tests, not guest/physical hardware tests."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("m6_runtime_evidence", ROOT/"scripts/m6_runtime_evidence.py")
m6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m6)
SHA = "a" * 40
DIGEST = "b" * 64
RX = "c" * 64
TX = "d" * 64


def sample():
    cross = {"source_sha": SHA, "cross_compiler_7c": "pass",
             "arm64_pci_driver_7c": "pass", "arm64_paqfs_userspace": "pass",
             "arm64_factotum_userspace": "pass", "arm64_kernel_link": "pass"}
    boot = {"schema": "ryzova-m5-arm64-native-qemu/v1", "source_sha": SHA,
            "arm64_kernel_link": "pass", "source_built_kernel_sha256": DIGEST,
            "independent_kernel_sha256_verified": True,
            "arm64_qemu_boot_observed": True, "outcome": "kernel-boot-observed"}
    runtime = {"schema": "ryzova-m6-arm64-guest-runtime/v1", "source_sha": SHA,
               "kernel_sha256": DIGEST,
               "virtio_net": {"driver": "virtio-net", "guest_rx_packets": 2,
                              "guest_tx_packets": 2, "host_rx_packets": 2,
                              "host_tx_packets": 2, "host_tx_sha256": RX,
                              "guest_rx_sha256": RX, "guest_tx_sha256": TX,
                              "host_rx_sha256": TX},
               "virtio_block": {"driver": "virtio-blk", "guest_written_bytes": 4096,
                                "flush_acknowledged": True, "guest_write_sha256": DIGEST,
                                "guest_readback_sha256": DIGEST,
                                "host_after_flush_sha256": DIGEST},
               "smp_irq": {"online_cpus": 2, "delivered_irqs": 150,
                           "irq_storm_recovered": True,
                           "registration_race_passed": True},
               "dma_iommu": {"mapping_failure_rejected": True,
                             "dma_bounds_negative_passed": True,
                             "detach_cleanup_passed": True}}
    return cross, boot, runtime


class M6RuntimeTests(unittest.TestCase):
    def test_missing_reports_fail_closed(self):
        gate = m6.evaluate({}, {}, {}, SHA)
        self.assertFalse(any(gate["checks"].values()))
        self.assertFalse(gate["hardware_release_ready"])
        self.assertEqual(gate["newly_certified_physical_models"], 0)

    def test_synthetic_consistent_inputs_still_never_certify_hardware(self):
        gate = m6.evaluate(*sample(), SHA)
        self.assertTrue(all(gate["checks"].values()))
        self.assertTrue(gate["all_runtime_observations_consistent"])
        self.assertFalse(gate["hardware_release_ready"])
        self.assertEqual(gate["newly_certified_physical_models"], 0)
        self.assertIn("independent-runtime-attestation-required", gate["blockers"])

    def test_wrong_source_or_boot_digest_blocks_runtime(self):
        cross, boot, runtime = sample()
        cross["source_sha"] = "e" * 40
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["arm64_qemu_boot_observed"])
        cross, boot, runtime = sample()
        boot["source_built_kernel_sha256"] = "f" * 64
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["virtio_net_host_guest_digests_consistent_unattested"])

    def test_compiler_success_cannot_replace_link_and_boot(self):
        cross, boot, runtime = sample()
        cross["arm64_kernel_link"] = "blocked"
        gate = m6.evaluate(cross, boot, runtime, SHA)
        self.assertTrue(gate["checks"]["native_arm64_source_compiled"])
        self.assertFalse(gate["checks"]["arm64_qemu_boot_observed"])
        self.assertFalse(gate["checks"]["virtio_block_host_guest_digests_consistent_unattested"])

    def test_network_bidirectional_proof_required(self):
        cross, boot, runtime = sample()
        runtime["virtio_net"]["host_rx_sha256"] = "0" * 64
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["virtio_net_host_guest_digests_consistent_unattested"])
        cross, boot, runtime = sample()
        runtime["virtio_net"]["guest_tx_packets"] = 0
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["virtio_net_host_guest_digests_consistent_unattested"])

    def test_block_flush_and_readback_required(self):
        cross, boot, runtime = sample()
        runtime["virtio_block"]["flush_acknowledged"] = False
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["virtio_block_host_guest_digests_consistent_unattested"])
        cross, boot, runtime = sample()
        runtime["virtio_block"]["guest_readback_sha256"] = "0" * 64
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["virtio_block_host_guest_digests_consistent_unattested"])

    def test_irq_and_dma_negative_cases(self):
        cross, boot, runtime = sample()
        runtime["smp_irq"]["online_cpus"] = 1
        runtime["dma_iommu"]["detach_cleanup_passed"] = False
        gate = m6.evaluate(cross, boot, runtime, SHA)
        self.assertFalse(gate["checks"]["smp_irq_stress_observations_consistent_unattested"])
        self.assertFalse(gate["checks"]["dma_lifecycle_observations_consistent_unattested"])

    def test_reject_bool_counters_and_malformed_input(self):
        cross, boot, runtime = sample()
        runtime["virtio_net"]["host_tx_packets"] = True
        self.assertFalse(m6.evaluate(cross, boot, runtime, SHA)["checks"]["virtio_net_host_guest_digests_consistent_unattested"])
        with self.assertRaises(ValueError):
            m6.evaluate([], {}, {}, SHA)
        with self.assertRaises(ValueError):
            m6.evaluate({}, {}, {}, "not-a-commit")


if __name__ == "__main__":
    unittest.main()
