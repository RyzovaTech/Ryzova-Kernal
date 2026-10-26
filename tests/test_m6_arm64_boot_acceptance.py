# SPDX-License-Identifier: AGPL-3.0-only
"""M6.1 CI evidence-gate contract tests; synthetic fixtures, not ARM64 boots."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "m6_arm64_boot_acceptance", ROOT / "scripts/m6_arm64_boot_acceptance.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA = "a" * 40
DIGEST = "b" * 64


def fixture():
    cross = {
        "source_sha": SHA,
        "cross_compiler_7c": "pass",
        "arm64_pci_driver_7c": "pass",
        "arm64_bootstrap_libraries_complete": True,
        "arm64_bootstrap_libraries": {lib: "pass" for lib in gate.REQUIRED_LIBRARIES},
        "arm64_paqfs_userspace": "pass",
        "arm64_factotum_userspace": "pass",
        "arm64_kernel_link": "pass",
        "arm64_fat_copy_verified": True,
        "arm64_uimage_guest_sha256": DIGEST,
    }
    boot = {
        "schema": "ryzova-m5-arm64-native-qemu/v1",
        "source_sha": SHA,
        "arm64_kernel_link": "pass",
        "source_built_kernel_sha256": DIGEST,
        "independent_kernel_sha256_verified": True,
        "arm64_qemu_boot_observed": True,
        "outcome": "kernel-boot-observed",
        "release_status": "blocked",
        "newly_certified_physical_models": 0,
    }
    return cross, boot


class M6NativeBootAcceptance(unittest.TestCase):
    def test_missing_evidence_must_block(self):
        report = gate.evaluate({}, {}, SHA)
        self.assertFalse(report["arm64_qemu_boot_accepted"])
        self.assertEqual(report["newly_certified_physical_models"], 0)

    def test_synthetic_valid_consistency_does_not_certify_hardware(self):
        report = gate.evaluate(*fixture(), SHA)
        self.assertTrue(report["arm64_qemu_boot_accepted"])
        self.assertFalse(report["physical_hardware_certified"])
        self.assertEqual(report["newly_certified_physical_models"], 0)

    def test_missing_any_one_library_blocks_kernel_qualification(self):
        for lib in gate.REQUIRED_LIBRARIES:
            cross, boot = fixture()
            cross["arm64_bootstrap_libraries"][lib] = "blocked"
            report = gate.evaluate(cross, boot, SHA)
            self.assertFalse(report["checks"]["all_target_libraries_built"], lib)
            self.assertFalse(report["arm64_qemu_boot_accepted"], lib)

    def test_wrong_checkout_and_hash_fail(self):
        cross, boot = fixture()
        cross["source_sha"] = "0" * 40
        self.assertFalse(gate.evaluate(cross, boot, SHA)["arm64_qemu_boot_accepted"])
        cross, boot = fixture()
        boot["source_built_kernel_sha256"] = "0" * 64
        self.assertFalse(gate.evaluate(cross, boot, SHA)["checks"]["arm64_uimage_digest_verified"])

    def test_compiler_only_cannot_claim_linked_or_booted(self):
        cross, boot = fixture()
        cross["arm64_kernel_link"] = "blocked"
        boot["arm64_qemu_boot_observed"] = False
        report = gate.evaluate(cross, boot, SHA)
        self.assertTrue(report["checks"]["arm64_native_7c_compiled"])
        self.assertFalse(report["arm64_qemu_boot_accepted"])

    def test_image_copy_or_boot_output_required(self):
        cross, boot = fixture()
        cross["arm64_fat_copy_verified"] = False
        self.assertFalse(gate.evaluate(cross, boot, SHA)["arm64_qemu_boot_accepted"])
        cross, boot = fixture()
        boot["outcome"] = "kernel-boot-unconfirmed"
        self.assertFalse(gate.evaluate(cross, boot, SHA)["arm64_qemu_boot_accepted"])

    def test_any_false_hardware_claim_rejected(self):
        cross, boot = fixture()
        boot["newly_certified_physical_models"] = 1
        self.assertFalse(gate.evaluate(cross, boot, SHA)["checks"]["not_a_hardware_release"])
        cross, boot = fixture()
        boot["release_status"] = "ready"
        self.assertFalse(gate.evaluate(cross, boot, SHA)["checks"]["not_a_hardware_release"])

    def test_malformed_checkout_rejected(self):
        with self.assertRaises(ValueError):
            gate.evaluate({}, {}, "invalid")


if __name__ == "__main__":
    unittest.main()
