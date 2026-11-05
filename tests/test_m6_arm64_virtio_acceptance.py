# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic M6.2 VirtIO evidence-contract tests; never actual QEMU proof."""
import importlib.util
from pathlib import Path
import tempfile
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "m6_virtio_acceptance", ROOT/"scripts/m6_arm64_virtio_acceptance.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

HEAD = "a"*40
SHA = "b"*64


def fixtures():
    boot = {
        "schema": "ryzova-m5-arm64-native-qemu/v1",
        "source_sha": HEAD,
        "arm64_kernel_link": "pass",
        "arm64_qemu_boot_observed": True,
        "arm64_boot_panic_observed": False,
        "outcome": "kernel-boot-observed",
        "independent_kernel_sha256_verified": True,
        "source_built_kernel_sha256": SHA,
        "release_status": "blocked",
        "newly_certified_physical_models": 0,
    }
    io = {
        "schema": "ryzova-m6-arm64-virtio-functional/v1",
        "source_sha": HEAD,
        "expected_uimage_sha256": SHA,
        "verified_uimage_sha256": True,
        "guest_shell_reached": True,
        "qemu_virtio_devices_attached": True,
        "root_disk_copy_on_write": True,
        "http_guest_request_observed": True,
        "host_fixture_requests": 1,
        "guest_network_digest_verified": True,
        "arm64_virtio_network_verified": True,
        "guest_disk_write_status_ok": True,
        "guest_disk_read_digest_verified": True,
        "host_ephemeral_disk_write_verified": True,
        "arm64_virtio_storage_verified": True,
        "outcome": "guest-virtio-io-observed",
        "completed_guest_stages": [0, 1, 2, 3],
        "release_status": "blocked",
        "newly_certified_physical_models": 0,
        "physical_hardware_certified": False,
    }
    return boot, io


class M6VirtioAcceptance(unittest.TestCase):
    def test_no_evidence_means_blocked(self):
        r = gate.evaluate({}, {}, HEAD)
        self.assertFalse(r["m6_2_virtio_functional_accepted"])
        self.assertEqual(r["newly_certified_physical_models"], 0)

    def test_synthetic_complete_contract_not_hardware_qualification(self):
        r = gate.evaluate(*fixtures(), HEAD)
        self.assertTrue(r["m6_2_virtio_functional_accepted"])
        self.assertFalse(r["physical_hardware_certified"])

    def test_no_m6_1_boot_or_hash_rejects_all_guest_io(self):
        for field, invalid in (
            ("arm64_qemu_boot_observed", False),
            ("arm64_kernel_link", "blocked"),
            ("independent_kernel_sha256_verified", False),
            ("source_built_kernel_sha256", None),
        ):
            boot, io = fixtures()
            boot[field] = invalid
            self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"], field)

    def test_native_kernel_panic_never_qualifies_virtio_data_plane(self):
        boot, io = fixtures()
        boot["arm64_boot_panic_observed"] = True
        self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"])

    def test_wrong_checkout_or_uimage_rejected(self):
        boot, io = fixtures()
        io["source_sha"] = "c"*40
        self.assertFalse(gate.evaluate(boot, io, HEAD)["checks"]["same_exact_checkout"])
        boot, io = fixtures()
        io["expected_uimage_sha256"] = "c"*64
        self.assertFalse(gate.evaluate(boot, io, HEAD)["checks"]["m6_2_boots_exact_native_uimage"])

    def test_no_verified_disposable_root_image_blocks_io_acceptance(self):
        boot, io = fixtures()
        io["root_disk_copy_on_write"] = False
        report = gate.evaluate(boot, io, HEAD)
        self.assertFalse(report["m6_2_virtio_functional_accepted"])

    def test_no_guest_shell_or_device_blocks(self):
        for field in ("guest_shell_reached", "qemu_virtio_devices_attached"):
            boot, io = fixtures()
            io[field] = False
            self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"], field)

    def test_no_host_http_request_or_guest_checksum_blocks(self):
        for field, bad in (
            ("http_guest_request_observed", False),
            ("host_fixture_requests", 0),
            ("guest_network_digest_verified", False),
            ("arm64_virtio_network_verified", False),
        ):
            boot, io = fixtures()
            io[field] = bad
            self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"], field)

    def test_no_guest_disk_write_readback_or_host_verification_blocks(self):
        for field in (
            "guest_disk_write_status_ok",
            "guest_disk_read_digest_verified",
            "host_ephemeral_disk_write_verified",
            "arm64_virtio_storage_verified",
        ):
            boot, io = fixtures()
            io[field] = False
            self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"], field)

    def test_all_guest_stages_are_required(self):
        for stage in range(4):
            boot, io = fixtures()
            io["completed_guest_stages"].remove(stage)
            self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"])

    def test_wrong_result_or_hardware_release_attempt_blocked(self):
        for field, bad in (
            ("outcome", "guest-virtio-io-incomplete"),
            ("release_status", "ready"),
            ("newly_certified_physical_models", 1),
            ("physical_hardware_certified", True),
        ):
            boot, io = fixtures()
            io[field] = bad
            self.assertFalse(gate.evaluate(boot, io, HEAD)["m6_2_virtio_functional_accepted"], field)

    def test_reports_read_from_files_are_size_and_type_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/"evidence.json"
            with self.assertRaises(ValueError):
                gate.read_json(p)
            p.write_text("[]")
            with self.assertRaises(ValueError):
                gate.read_json(p)
            p.write_text(json.dumps({"pass": False}))
            self.assertEqual(gate.read_json(p), {"pass": False})

    def test_invalid_checkout_sha_rejected(self):
        with self.assertRaises(ValueError):
            gate.evaluate({}, {}, "badsha")


if __name__ == "__main__":
    unittest.main()
