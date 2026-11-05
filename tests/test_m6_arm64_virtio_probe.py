# SPDX-License-Identifier: AGPL-3.0-only
"""M6.2 strict host/guest evidence contract tests (synthetic, not hardware)."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "m6armvirtio", ROOT / "scripts/m6_arm64_virtio_probe.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class VirtioContract(unittest.TestCase):
    def setUp(self):
        self.net = b"RYZOVA_M6_NET_DATA_example\n"
        self.disk = b"RYZOVA_M6_DISK_example\n"
        self.serial = (
            b"term%\r\nM6_STAGE_0\r\n" +
            m.sha256(self.net).encode() + b"\t-\r\nM6_STAGE_1\r\n" +
            b"M6_DISK_WRITE_STATUS_\r\nM6_STAGE_2\r\n" +
            m.sha256(self.disk).encode() + b"\t/tmp/m6-disk-read\r\nM6_STAGE_3\r\n"
        )

    def adjudicate(self, **overrides):
        inputs = dict(
            serial=self.serial, net_payload=self.net, disk_payload=self.disk,
            host_get_count=1, host_disk_prefix=self.disk,
            stages={0, 1, 2, 3}, shell_reached=True)
        inputs.update(overrides)
        return m.classify(**inputs)

    def test_synthetic_contract_requires_both_actual_host_and_guest_observations(self):
        report = self.adjudicate()
        self.assertTrue(report["arm64_virtio_network_verified"])
        self.assertTrue(report["arm64_virtio_storage_verified"])
        self.assertTrue(report["host_ephemeral_disk_write_verified"])

    def test_no_network_request_is_not_network_io(self):
        self.assertFalse(self.adjudicate(host_get_count=0)[
            "arm64_virtio_network_verified"])
        self.assertFalse(self.adjudicate(serial=b"term%\r\nM6_STAGE_1\r\n")[
            "arm64_virtio_network_verified"])

    def test_guest_only_disk_claim_without_host_write_is_rejected(self):
        result = self.adjudicate(host_disk_prefix=b"\x00" * len(self.disk))
        self.assertFalse(result["arm64_virtio_storage_verified"])
        self.assertFalse(result["host_ephemeral_disk_write_verified"])

    def test_host_write_only_without_guest_read_is_rejected(self):
        result = self.adjudicate(stages={0, 1, 2})
        self.assertFalse(result["arm64_virtio_storage_verified"])

    def test_missing_guest_shell_blocks_both(self):
        result = self.adjudicate(shell_reached=False)
        self.assertFalse(result["arm64_virtio_network_verified"])
        self.assertFalse(result["arm64_virtio_storage_verified"])

    def test_shell_echo_is_not_execution_status(self):
        fake = b"term% echo M6_DISK_WRITE_STATUS_$status; echo M6_STAGE_2\r\n"
        self.assertFalse(m.standalone_marker(fake, "M6_DISK_WRITE_STATUS_"))
        self.assertFalse(m.standalone_marker(fake, "M6_STAGE_2"))

    def test_guest_commands_use_disposable_sda_and_explicit_io(self):
        cmds = m._guest_commands(self.disk)
        self.assertEqual(len(cmds), 4)
        self.assertTrue(all(len(c) < 190 for c in cmds))
        self.assertTrue(any("hget http://10.0.2.100" in c for c in cmds))
        self.assertTrue(any("> /dev/sd01/data" in c for c in cmds))
        self.assertTrue(any("dd -if /dev/sd01/data" in c for c in cmds))
        self.assertFalse(any("> /dev/sd00/data" in c for c in cmds))
        self.assertTrue(any("sha1sum -2 256 /tmp/m6-disk-read" in c for c in cmds))

    def test_valid_kernel_requires_existing_root_disk_before_qemu(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            kernel = out / "synthetic-not-a-real-kernel.u"
            kernel.write_bytes(b"not a real AArch64 boot image")
            from hashlib import sha256
            image_digest = sha256(kernel.read_bytes()).hexdigest()
            report = m.run_probe(kernel, "a" * 40, image_digest, out,
                                 root_overlay=out / "not-present.qcow2")
            self.assertEqual(report["outcome"], "rootfs-disk-missing")
            self.assertFalse(report["qemu_virtio_devices_attached"])
            self.assertFalse(report["arm64_virtio_network_verified"])
            self.assertFalse(report["arm64_virtio_storage_verified"])
            self.assertEqual(report["newly_certified_physical_models"], 0)

    def test_host_root_disk_remains_copy_on_write(self):
        source = (ROOT / "scripts/m6_arm64_virtio_probe.py").read_text()
        self.assertIn('"arm64-root-cow.qcow2"', source)
        self.assertIn('"qemu-img", "create", "-f", "qcow2"', source)
        self.assertIn('id=m6root,format=qcow2,file={root_disk}', source)
        self.assertIn('id=m6disk,format=raw,file={disk}', source)
        self.assertIn('"root_disk_copy_on_write": False', source)

    def test_invalid_kernel_sha_never_starts_qemu(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            kernel = out/"uimage.bin"
            kernel.write_bytes(b"not a real kernel")
            result = m.run_probe(kernel, "notasha", "b"*64, out)
            self.assertEqual(result["outcome"], "invalid-source-sha")
            self.assertFalse(result["arm64_virtio_network_verified"])
            self.assertFalse(result["arm64_virtio_storage_verified"])
            self.assertEqual(result["newly_certified_physical_models"], 0)
            self.assertTrue((out/"m6-arm64-virtio-probe.json").is_file())

    def test_mismatch_kernel_digest_never_starts_qemu(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            kernel = out/"uimage.bin"
            kernel.write_bytes(b"not a real kernel")
            result = m.run_probe(kernel, "a"*40, "b"*64, out)
            self.assertEqual(result["outcome"], "kernel-digest-mismatch")
            self.assertFalse(result["arm64_virtio_storage_verified"])
            self.assertFalse(result["arm64_virtio_network_verified"])


if __name__ == "__main__":
    unittest.main()
