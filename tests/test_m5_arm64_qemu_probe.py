# SPDX-License-Identifier: AGPL-3.0-only
"""M5 arm64 native uImage extraction/QEMU probe must fail closed."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("m5armprobe", ROOT/"scripts/m5_arm64_qemu_probe.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Arm64QemuProbeTest(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix="m5-qemu-test-")
        self.out=Path(self.t.name)
        self.orig=(module.OUT,module.CROSS,module.SERIAL)
        module.OUT=self.out
        module.CROSS=self.out/"cross.json"
        module.SERIAL=self.out/"native-serial.log"

    def tearDown(self):
        module.OUT,module.CROSS,module.SERIAL=self.orig
        self.t.cleanup()

    def test_nonlinked_image_never_invokes_qemu_or_certifies_hardware(self):
        module.CROSS.write_text(json.dumps({
            "source_sha":"a"*40,
            "cross_compiler_7c":"pass",
            "arm64_pci_driver_7c":"pass",
            "arm64_kernel_link":"blocked"}))
        report=module.probe(self.out/"not-an-image.qcow2")
        self.assertFalse(report["arm64_qemu_boot_observed"])
        self.assertFalse(report["arm64_virtio_network_verified"])
        self.assertFalse(report["arm64_virtio_storage_verified"])
        self.assertEqual(report["newly_certified_physical_models"],0)
        self.assertEqual(report["outcome"],"not-booted-native-link-incomplete")

    def test_compiled_image_needs_independent_copy_and_sha_evidence(self):
        module.CROSS.write_text(json.dumps({
            "source_sha":"b"*40,
            "arm64_kernel_link":"pass"}))
        module.SERIAL.write_text("term% echo M5_ARM64_COPY_STATUS_$status\n")
        with self.assertRaises(RuntimeError):
            module.probe(self.out/"not-an-image.qcow2")
        module.SERIAL.write_text("M5_ARM64_COPY_STATUS_\r\n")
        with self.assertRaises(RuntimeError):
            module.probe(self.out/"not-an-image.qcow2")

    def test_fat_candidate_scan_rejects_unmarked_sector(self):
        disk=self.out/"fat.raw"
        with disk.open("wb") as f:
            f.write(b"\0"*512)
            b=bytearray(512)
            b[0]=0xeb
            b[510:512]=b"\x55\xaa"
            b[54:59]=b"FAT16"
            f.write(b)
            f.write(b"\0"*512)
        self.assertEqual(list(module.find_fat(disk)),[512])

    def test_sha256_matches_known_data(self):
        from hashlib import sha256
        f=self.out/"hash.bin"
        f.write_bytes(b"Ryzova ARM64 source evidence")
        self.assertEqual(module.sha256(f),sha256(f.read_bytes()).hexdigest())

if __name__=="__main__":
    unittest.main()
