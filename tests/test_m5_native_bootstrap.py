# SPDX-License-Identifier: AGPL-3.0-only
"""M5 ARM64 source/bootstrap evidence and M6 transition gates."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from m5_platform_audit import audit
from m5_server_gates import report


class M5Bootstrap(unittest.TestCase):
    def test_native_port_and_bootstrap_deps(self):
        s=(ROOT/"scripts/phase3-native-build.py").read_text()
        for required in ("7c -o /tmp/m5ecam.7 m5ecam.c",
                         "7c -o /tmp/m5pciqemu.7 pciqemu.c",
                         "objtype=arm64 mk 7.paqfs",
                         "objtype=arm64 mk 7.factotum",
                         "mk 9qemu",
                         "M5_ARM64_7C_STATUS_",
                         "M5_ARM64_PCI_7C_STATUS_",
                         "M5_ARM64_PAQFS_STATUS_",
                         "M5_ARM64_FACTOTUM_STATUS_",
                         "M5_ARM64_MK_STATUS_"):
            self.assertIn(required,s)
        self.assertIn("if not cross_ok:",s)
        self.assertIn('"arm64_qemu_boot": "not-tested"',s)
        self.assertIn('"full_m5_1_complete": False',s)

    def test_shell_echo_does_not_count_as_native_evidence(self):
        s=(ROOT/"scripts/phase3-native-build.py").read_text()
        self.assertIn(r'r"(?:^|\r?\n)M5_ARM64_7C_STATUS_\s*(?:\r?\n)"',s)
        self.assertIn(r'r"(?:^|\r?\n)M5_ARM64_PCI_7C_STATUS_\s*(?:\r?\n)"',s)
        echoed="term% echo M5_ARM64_MK_STATUS_$status\r\n"
        rx=r"(?:^|\r?\n)M5_ARM64_MK_STATUS_\s*(?:\r?\n)"
        self.assertIsNone(re.search(rx,echoed))
        self.assertIsNotNone(re.search(rx,"\r\nM5_ARM64_MK_STATUS_\r\n"))

    def test_m6_planning_and_release_not_confused(self):
        source=audit(ROOT)
        for cross in (None, {"cross_compiler_7c":"pass",
                              "arm64_kernel_link":"blocked"},
                      {"cross_compiler_7c":"pass",
                       "arm64_kernel_link":"pass"}):
            x=report(source,cross=cross)
            self.assertFalse(x["m5_full_complete"])
            self.assertTrue(x["ready_for_m6_planning"])
            self.assertFalse(x["ready_for_m6_hardware_release"])
            self.assertEqual(x["physical_hardware_models_newly_certified"],0)
            self.assertFalse(x["m5_1_arm64_boot_certified"])

    def test_server_and_old_pc_profiles_remain(self):
        manifest=json.loads((ROOT/"ryzova/drivers/m5-platform-matrix.json").read_text())
        self.assertEqual([p["id"] for p in manifest["profiles"]],
                         ["arm64-qemu-server","amd64-server","legacy-amd64"])
        self.assertEqual(manifest["certified_models"],0)
        self.assertFalse(manifest["automatic_cross_arch_driver_bind"])


if __name__=="__main__":
    unittest.main()
