# SPDX-License-Identifier: AGPL-3.0-only
"""W8 real Windows reference -> engineering-only candidate, never a guest PASS."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compact_windows_w8_triage import triage


def reference():
    apps = []
    for i, name in enumerate(("sort", "findstr", "where")):
        apps.append({
            "name": name, "binary_sha256": hashlib.sha256(name.encode()).hexdigest(),
            "binary_bytes": 1024+i*10,
            "windows_reference": {
                "reference_passed": True, "exit_code": 0, "stdout_bytes": 11,
                "stdout_sha256": "a"*64, "stderr_sha256": "b"*64,
            },
            "pe_import_audit": {
                "architecture": "amd64", "direct_imports": 3+i,
                "modules": ["kernel32.dll"], "missing_or_ordinal_imports": [
                    "kernel32.dll!Unknown"+str(n) for n in range(i)
                ], "delay_load_requires_runtime_resolver": False,
                "delay_load_modules": [], "runtime_directories_unqualified": [],
            },
            "pe_audit_rejection": None,
            "guest_execution_verified": False,
            "transitive_dll_closure_verified": False,
            "application_workflow_qualified": False,
        })
    return {
        "schema": "compact-windows-real-app-reference/v1",
        "source_commit": "c"*40, "runner_image_version": "20261025.1",
        "windows_os_version": "10.0.20348",
        "windows_reference_passed": True,
        "native_guest_execution_qualified": False,
        "windows_v1_release_qualified": False,
        "reference_applications": apps,
    }


class W8CandidateTriageTests(unittest.TestCase):
    def test_deterministic_shortlist_is_never_native_guest_approval(self):
        r = triage(reference())
        self.assertEqual(r["candidate_for_engineering_only"], "sort")
        self.assertEqual(r["reference_app_count"], 3)
        self.assertFalse(r["candidate_is_guest_qualified"])
        self.assertFalse(r["native_guest_execution_qualified"])
        self.assertFalse(r["windows_v1_release_qualified"])
        self.assertTrue(all(not x["guest_execution_verified"] for x in r["apps"]))
        self.assertEqual(r["apps"][2]["missing_direct_imports"],
                         ["kernel32.dll!Unknown0", "kernel32.dll!Unknown1"])

    def test_candidate_minimizes_missing_imports_not_application_name(self):
        data = reference()
        data["reference_applications"][0]["pe_import_audit"]["missing_or_ordinal_imports"] = ["kernel32.dll!Unknown"]
        data["reference_applications"][1]["pe_import_audit"]["missing_or_ordinal_imports"] = []
        result = triage(data)
        self.assertEqual(result["candidate_for_engineering_only"], "findstr")
        self.assertFalse(result["candidate_is_guest_qualified"])

    def test_oversized_file_and_unimplemented_delay_imports_are_blockers(self):
        data = reference()
        data["reference_applications"][0]["binary_bytes"] = 4*1024*1024+1
        data["reference_applications"][1]["pe_import_audit"]["delay_load_modules"] = ["user32.dll"]
        data["reference_applications"][2]["pe_audit_rejection"] = "PE import overflow"
        data["reference_applications"][2]["pe_import_audit"] = None
        result = triage(data)
        self.assertIsNone(result["candidate_for_engineering_only"])
        self.assertTrue(all(not x["structurally_within_current_caps"] for x in result["apps"]))
        self.assertIn("source-available", result["next_step"])
        self.assertFalse(result["native_guest_execution_qualified"])

    def test_forged_reference_or_guest_success_rejected(self):
        for edit in (
            lambda x: x.update(windows_reference_passed=False),
            lambda x: x.update(native_guest_execution_qualified=True),
            lambda x: x.update(windows_v1_release_qualified=True),
            lambda x: x.update(source_commit="not a SHA"),
            lambda x: x["reference_applications"][1].update(guest_execution_verified=True),
            lambda x: x["reference_applications"][1].update(application_workflow_qualified=True),
            lambda x: x["reference_applications"][2]["windows_reference"].update(exit_code=1),
            lambda x: x["reference_applications"][2].update(binary_sha256="123"),
            lambda x: x["reference_applications"].append(copy.deepcopy(x["reference_applications"][0])),
            lambda x: x["reference_applications"][1]["pe_import_audit"].update(direct_imports=33),
        ):
            data = reference()
            edit(data)
            with self.subTest(edit=edit):
                if data["reference_applications"][1]["pe_import_audit"]["direct_imports"] == 33:
                    result = triage(data)
                    self.assertFalse(result["apps"][1]["structurally_within_current_caps"])
                else:
                    with self.assertRaises(ValueError):
                        triage(data)

    def test_runtime_limits_mirror_current_windows_header(self):
        header = (ROOT/"ryzova/compat/windows/runtime.h").read_text()
        self.assertIn("#define CW_MAX_FILE (4U*1024U*1024U)", header)
        self.assertIn("#define CW_MAX_IMPORTS 32U", header)


if __name__ == "__main__":
    unittest.main()
