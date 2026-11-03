# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-0 static-only contract/provenance security tests."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compact_macos_m0_audit import (
    AUTHORITY, CAPABILITIES, CONTRACT, LIMITS, SOURCES,
    inspect, validate_contract,
)


class Mac0AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads((ROOT / CONTRACT).read_text(encoding="utf-8"))

    def test_frozen_mac0_contract_has_no_implicit_execution_authority(self):
        self.assertTrue(validate_contract(self.contract))
        self.assertEqual(self.contract["bounded_limits"], LIMITS)
        for name in CAPABILITIES:
            self.assertIs(self.contract["capabilities"][name], False, name)
        for name in AUTHORITY:
            self.assertIs(self.contract["authority"][name], False, name)

    def test_scope_escalation_and_linux_windows_confusion_fail_closed(self):
        for section, key in (
            ("capabilities", "native_rz_guest_execution"),
            ("capabilities", "macho_loader_and_mapping"),
            ("capabilities", "darwin_bsd_syscalls"),
            ("capabilities", "apple_silicon_arm64"),
            ("capabilities", "production_macos_app_compatibility"),
            ("authority", "host_syscall_forwarding"),
            ("authority", "host_filesystem_access"),
            ("authority", "code_signing_bypass"),
        ):
            with self.subTest(section=section, key=key):
                item = copy.deepcopy(self.contract)
                item[section][key] = True
                with self.assertRaises(ValueError):
                    validate_contract(item)
        for attr, bad in (
            ("target_architecture", "arm64"),
            ("profile", "darwin-entire-os-compatible"),
            ("supported_image", "MH_EXECUTE with dyld"),
        ):
            with self.subTest(attr=attr):
                item = copy.deepcopy(self.contract)
                item[attr] = bad
                with self.assertRaises(ValueError):
                    validate_contract(item)

    def test_increase_of_unreviewed_limits_or_extra_commands_is_denied(self):
        for name, value in (
            ("input_bytes", 1024 * 1024 * 1024),
            ("load_commands", 4096),
            ("segments", 256),
            ("segment_virtual_bytes", 2**40),
        ):
            with self.subTest(name=name):
                item = copy.deepcopy(self.contract)
                item["bounded_limits"][name] = value
                with self.assertRaises(ValueError):
                    validate_contract(item)
        item = copy.deepcopy(self.contract)
        item["load_command_allowlist"].append("LC_LOAD_DYLIB")
        with self.assertRaises(ValueError):
            validate_contract(item)

    def test_actual_source_inventory_is_sha256_pinned_and_not_runtime_evidence(self):
        report = inspect(ROOT)
        self.assertTrue(report["static_contract_accepted"])
        self.assertFalse(report["application_execution_verified"])
        self.assertFalse(report["native_kernel_guest_execution_verified"])
        self.assertFalse(report["mac1_to_mac7_completed"])
        self.assertFalse(report["production_release_allowed"])
        self.assertEqual(set(report["source_sha256"]), {CONTRACT, *SOURCES})
        for name, digest in report["source_sha256"].items():
            self.assertEqual(digest, hashlib.sha256((ROOT / name).read_bytes()).hexdigest())

    def test_missing_and_symlinked_sources_deny_provenance_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repository"
            for name in (CONTRACT, *SOURCES):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, target)
            self.assertTrue(inspect(root)["static_contract_accepted"])
            target = root / SOURCES[0]
            target.unlink()
            with self.assertRaises(ValueError):
                inspect(root)
            outside = Path(temp) / "out-of-tree-source.c"
            outside.write_text("/* SPDX-License-Identifier: AGPL-3.0-only */\n")
            target.symlink_to(outside)
            with self.assertRaises(ValueError):
                inspect(root)

    def test_legacy_phase5_metadata_only_record_is_not_overwritten(self):
        original = json.loads((ROOT / "ryzova/compat/phase5-status.json").read_text())
        mac = original["platforms"]["macos"]
        self.assertIs(mac["metadata_parser"], True)
        self.assertIs(mac["darwin_mach_runtime"], False)
        self.assertIs(mac["application_execution_verified"], False)


if __name__ == "__main__":
    unittest.main()
