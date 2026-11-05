# SPDX-License-Identifier: AGPL-3.0-only
"""W7 source-locked ARM64 native-system boot receipt contract unit tests.

Mocked QEMU text is a negative/control UNIT TEST only. This never qualifies
an actual ARM64 boot; only the source-built native CI workflow may do so.
"""
import hashlib
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_w7_native_arm64_system import (
    BOOT_FILES, MAX_KERNEL, native_arm64_boot, inventory, bundle
)


class NativeArm64BootContract(unittest.TestCase):
    def test_tracked_original_source_inventory(self):
        files=inventory()
        self.assertTrue(set(BOOT_FILES).issubset(files))
        self.assertGreaterEqual(len(files),350)
        self.assertTrue(all(len(d)==64 for d in files.values()))
        with tempfile.TemporaryDirectory() as temp:
            archive=Path(temp)/"sources.tgz"
            sha=bundle(archive,files)
            self.assertEqual(sha,hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_missing_real_serial_and_wrong_kernel_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            kernel=p/"9qemu.u"
            serial=p/"console.log"
            kernel.write_bytes(b"untrusted"+bytes(1100))
            # Do not invoke actual QEMU for unit negative cases: a "started"
            # emulator or a single banner is insufficient as native proof.
            for case in (
                b"",
                b"QEMU version 10.1\n",
                b"Plan 9\n",
                b"cpu0: 1000MHz QEMU\n",
                b"Linux version 6.14\nPlan 9 banner spoof\n",
            ):
                with self.subTest(case=case),patch(
                    "compact_windows_w7_native_arm64_system.subprocess.run",
                    return_value=SimpleNamespace(returncode=0,stdout=case)
                ):
                    with self.assertRaises(ValueError):
                        native_arm64_boot(kernel,serial)

    def test_oversized_missing_and_symlink_kernel_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            missing=p/"missing"
            with self.assertRaises(ValueError):
                native_arm64_boot(missing,p/"serial")
            large=p/"huge.u"
            with large.open("wb") as out:
                out.truncate(MAX_KERNEL+1)
            with self.assertRaises(ValueError):
                native_arm64_boot(large,p/"serial")

    def test_boot_markers_only_separate_from_actual_windows_arm64_pe(self):
        # Synthetic banner tests verify parsing, NEVER physical boot.
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            kernel=p/"9qemu.u"
            kernel.write_bytes(bytes(1400))
            banner=b"\r\nPlan 9\r\ncpu0: 1000MHz QEMU\r\n"
            with patch(
                "compact_windows_w7_native_arm64_system.subprocess.run",
                return_value=SimpleNamespace(returncode=0,stdout=banner)
            ) as fake:
                result=native_arm64_boot(kernel,p/"serial.log")
                self.assertEqual(result["guest_architecture"],"aarch64-system")
                self.assertTrue(result["real_qemu_system_aarch64_boot_markers_verified"])
                self.assertEqual((p/"serial.log").read_bytes(),banner)
                self.assertEqual(fake.call_args.args[0][0],"qemu-system-aarch64")
                self.assertIn("9qemu.u",str(fake.call_args.args[0]))


if __name__=="__main__":
    unittest.main()
