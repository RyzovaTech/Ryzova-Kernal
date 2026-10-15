#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 4.0 baseline/rollback CI unit tests (no external dependencies)."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ryzova_phase4", ROOT / "scripts/phase4-baseline.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class Phase4BaselineTests(unittest.TestCase):
    def test_kernel_input_classification(self):
        for path in (
            "sys/src/9/pc64/sdnvme.c",
            "sys/src/9/port/devryzova.c",
            "sys/include/u.h",
            "amd64/include/u.h",
            "ryzova/metadata/kernel-version.json",
            "scripts/phase3-native-build.py",
            "scripts/extract-9pc64.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(module.is_kernel_input(path))
        for path in ("docs/PHASE4-0.md", "README.md", "LICENSE.md", ".github/workflows/license-audit.yml"):
            with self.subTest(path=path):
                self.assertFalse(module.is_kernel_input(path))

    def test_recovery_branch_is_safe(self):
        for name in ("recovery/phase4-ci-drill", "recovery/phase4.0", "recovery/device-new"):
            self.assertTrue(module.validate_branch_name(name))
        for name in ("main", "recovery/../main", "recovery/x.lock", "recovery//x", "recovery/x;", "recovery/"):
            self.assertFalse(module.validate_branch_name(name))

    def test_baseline_pinned_source_valid(self):
        result = module.verify()
        self.assertTrue(result["automatic_9front_sync_absent"])
        self.assertEqual(result["baseline_commit"], "d6b1f3d8e78470f5ae9caf42d85deb983239e752")
        self.assertEqual(len(result["baseline_trees_verified"]), 4)
        self.assertFalse(result["production_release_authorized"])
        self.assertFalse(result["hardware_certified"])

    def test_recovery_dry_run_is_non_destructive(self):
        name = "recovery/phase4-unit-test-not-created"
        ref = f"refs/heads/{name}"
        before = subprocess.run(["git", "show-ref", "--verify", ref], cwd=ROOT, capture_output=True).returncode
        self.assertNotEqual(before, 0)
        result = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts/phase4-baseline.py"),
                "prepare-rollback", "--name", name,
                "--output", "artifacts/phase4/unit-test-rollback.json",
            ], cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = subprocess.run(["git", "show-ref", "--verify", ref], cwd=ROOT, capture_output=True).returncode
        self.assertNotEqual(after, 0)


if __name__ == "__main__":
    unittest.main()
