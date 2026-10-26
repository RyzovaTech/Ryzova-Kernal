# SPDX-License-Identifier: AGPL-3.0-only
"""M5 ARM64 source/bootstrap evidence and M6 transition gates."""
import ast
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

    def test_arm64_serial_stages_fit_safe_budget_and_have_unique_end_markers(self):
        source=(ROOT/"scripts/phase3-native-build.py").read_text()
        module=ast.parse(source)
        branch=next(n for n in module.body if isinstance(n,ast.If)
                    and isinstance(n.test,ast.Name) and n.test.id=="m5_arm64_native")
        env={"m5_arm64_native":True,"stages":[("preexisting","")] * 11}
        exec(compile(ast.Module(body=[branch],type_ignores=[]),
                     "<m5-arm64-stages>","exec"),env)
        built=env["stages"][11:]
        self.assertEqual(len(built),39)
        for ix,(name,command) in enumerate(built,11):
            self.assertLessEqual(len(command),190, name)
            self.assertTrue(command.endswith("; echo PHASE3_END_"+str(ix)),name)
        self.assertTrue(any("M5_ARM64_7C_STATUS_" in c for _,c in built))
        self.assertTrue(any("M5_ARM64_MK_STATUS_" in c for _,c in built))
        libs = ("libc", "libbio", "libflate", "libString", "libthread", "lib9p",
                "libmp", "libsec", "libip", "libdraw",
                "libmemdraw", "libmemlayer", "libauth", "libauthsrv")
        names = {name for name, _ in built}
        self.assertIn("m5-arm64-libdirs", names)
        for lib in libs:
            self.assertIn("m5-arm64-build-" + lib, names)
            self.assertIn("m5-arm64-verify-" + lib, names)
            self.assertTrue(any("M5_ARM64_" + lib.upper() + "_STATUS_" in c
                                for _, c in built))
            self.assertTrue(any("M5_ARM64_" + lib.upper() + "_ARTIFACT_" in c
                                for _, c in built))

    def test_arm64_native_library_tcq_time_budget_is_bounded(self):
        source=(ROOT/"scripts/phase3-native-build.py").read_text()
        workflow=(ROOT/".github/workflows/phase3-native-build.yml").read_text()
        self.assertIn("total_budget=1500 if m5_arm64_native else 750",source)
        self.assertIn('label.startswith("m5-arm64-build-") else 380',source)
        self.assertIn("timeout-minutes: 40",workflow)
        self.assertIn("if time.monotonic()-stage_start>stage_budget:",source)

    def test_arm64_library_failures_cannot_be_marked_linked(self):
        source=(ROOT/"scripts/phase3-native-build.py").read_text()
        for path in ("sys/src/libc", "sys/src/libbio", "sys/src/libflate",
                     "sys/src/libString", "sys/src/libthread", "sys/src/lib9p",
                     "sys/src/libmp", "sys/src/libsec",
                     "sys/src/libip", "sys/src/libdraw", "sys/src/libmemdraw",
                     "sys/src/libmemlayer", "sys/src/libauth", "sys/src/libauthsrv"):
            self.assertIn('"' + path + '"', source)
        self.assertIn('arm64_libraries_ok = all(arm64_libraries.values())', source)
        self.assertIn('arm64_libraries_ok and paqfs_ok and factotum_ok', source)
        self.assertIn('"arm64_bootstrap_libraries_complete": arm64_libraries_ok', source)
        self.assertIn('marks.get("m5-arm64-verify-" + lib)', source)


    def test_arm64_bootfs_install_and_fat_copy_must_be_evidenced(self):
        s=(ROOT/"scripts/phase3-native-build.py").read_text()
        self.assertIn('marks.get("m5-arm64-paqfs-install")', s)
        self.assertIn('marks.get("m5-arm64-factotum-install")', s)
        self.assertIn('M5_ARM64_PAQFS_INSTALL_', s)
        self.assertIn('M5_ARM64_FACTOTUM_INSTALL_', s)
        self.assertIn('marks.get("m5-arm64-copy")', s)
        self.assertIn('marks.get("m5-arm64-hash")', s)
        self.assertIn('cp 9qemu.u /n/9fat/9qemu.u && ', s)
        self.assertIn('cmp 9qemu.u /n/9fat/9qemu.u', s)
        self.assertIn('"arm64_fat_copy_verified": bool(arm64_fat_copy_ok)', s)
        self.assertIn('"arm64_uimage_guest_sha256": image_hashes[-1]', s)
        self.assertIn('"full_m5_1_complete": False', s)

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
