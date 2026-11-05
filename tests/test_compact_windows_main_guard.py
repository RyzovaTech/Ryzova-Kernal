# SPDX-License-Identifier: GPL-3.0-only
"""Mutational boundary tests for single Windows main integration."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_main_guard import allowed,validate_plan,validate_paths


class MainIntegrationGateTests(unittest.TestCase):
    def test_windows_files_allowed_and_foreign_sources_rejected(self):
        for good in (
          "ryzova/compat/windows/hjfs/main.c",
          "scripts/compact_windows_w6_native.py",
          "tests/test_compact_windows_w1.py",
          "tests/fixtures/windows_w4_reference.c",
          "docs/COMPACT-WINDOWS-W6.md",
          ".github/workflows/compact-windows-main-integration.yml",
          "ryzova/compact/windows-v1-plan.json",
        ):
            with self.subTest(good=good):
                self.assertTrue(allowed(good))
        for bad in (
          "ryzova/compat/linux/cpu.c",
          "sys/src/9/pc/ether.c",
          ".github/workflows/sync-9front.yml",
          "drivers/e1000.c",
          ".github/workflows/phase3-native-build.yml",
          "ryzova/compat/windows/../linux/cpu.c",
          "",
          None,
        ):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                validate_paths(["docs/COMPACT-WINDOWS-W6.md",bad])
        self.assertTrue(validate_paths(["ryzova/compact/windows-v1-plan.json"]))
        with self.assertRaises(ValueError):
            validate_paths([])

    def test_bounded_native_does_not_promote_full_release(self):
        plan=json.loads((ROOT/"ryzova/compact/windows-v1-plan.json").read_text())
        self.assertTrue(validate_plan(plan))
        for field,value in (
            ("windows_execution_qualified",True),
            ("general_windows_compatibility_claim",True),
            ("native_amd64_qemu_profile_qualified",False),
        ):
            with self.subTest(field=field),self.assertRaises(ValueError):
                altered=copy.deepcopy(plan)
                altered[field]=value
                validate_plan(altered)
        for field,value in (
            ("bounded_native_phase_complete",False),
            ("full_phase_complete",True),
            ("physical_hardware","passed"),
            ("arm64_windows","passed"),
            ("boot_hjfs_sigkill_persistence","qualified"),
        ):
            with self.subTest(field=field),self.assertRaises(ValueError):
                altered=copy.deepcopy(plan)
                altered["w6_qualification"][field]=value
                validate_plan(altered)
        altered=copy.deepcopy(plan)
        altered["requirements"][0]["state"]="passed"
        with self.assertRaises(ValueError):
            validate_plan(altered)


if __name__=="__main__":
    unittest.main()
