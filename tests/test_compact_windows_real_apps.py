# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only W8 real Windows binary reference and missing-import boundary tests."""
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compact_windows_real_apps import APPLICATIONS, analyze, collect, verify_reference


def proc(stdout, *, code=0, stderr=b""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class WindowsNamedReferenceTests(unittest.TestCase):
    def test_three_genuine_console_behaviours(self):
        values = {
            "sort": b"apple\r\norange\r\n",
            "findstr": b"apple\r\napplesauce\r\n",
            "where": b"C:\\Windows\\System32\\cmd.exe\r\n",
        }
        for name, raw in values.items():
            with self.subTest(name=name):
                r = verify_reference(name, proc(raw))
                self.assertTrue(r["reference_passed"])
                self.assertEqual(r["stdout_sha256"], hashlib.sha256(raw).hexdigest())

    def test_wrong_outputs_exit_unknown_app_and_oversized_outputs_fail_closed(self):
        cases = [
            ("sort", proc(b"orange\napple\n")),
            ("findstr", proc(b"apple\n", code=1)),
            ("where", proc(b"C:\\Other\\malware.exe\n")),
            ("sort", proc(b"a" * 16385)),
            ("another_app", proc(b"anything")),
        ]
        for name, output in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    verify_reference(name, output)

    def test_reference_runner_cannot_be_simulated_on_linux(self):
        with patch("compact_windows_real_apps.os.name", "posix"):
            with self.assertRaises(RuntimeError):
                collect({"schema": "compact-windows-plan/v1"})

    def test_named_application_set_is_fixed(self):
        self.assertEqual(tuple(x[0] for x in APPLICATIONS),
                         ("sort", "findstr", "where"))


class WindowsNamedInventoryTests(unittest.TestCase):
    def test_unknown_unbounded_or_unverified_input_rejected(self):
        sample = b"MZ" + b"\0" * 260
        for name, binary, receipt in (
            ("untrusted.exe", sample, {"reference_passed": True}),
            ("sort", b"MZ", {"reference_passed": True}),
            ("sort", sample, {"reference_passed": False}),
        ):
            with self.subTest(name=name, length=len(binary)):
                with self.assertRaises(ValueError):
                    analyze(name, binary, {}, receipt)

    def test_declared_imports_never_equal_guest_execution(self):
        data = b"MZ" + b"\0" * 260
        with patch("compact_windows_real_apps.discover", return_value={
            "architecture": "amd64",
            "declared_import_profile_covered": True,
            "missing_or_ordinal_imports": [],
            "guest_executable_verified": False,
        }):
            report = analyze("sort", data, {}, {"reference_passed": True})
        self.assertEqual(report["binary_sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse(report["guest_execution_verified"])
        self.assertFalse(report["transitive_dll_closure_verified"])
        self.assertFalse(report["application_workflow_qualified"])
        self.assertIsNone(report["pe_audit_rejection"])
        self.assertEqual(len(report["blocking_reasons"]), 2)

    def test_rejected_pe_missing_imports_and_wrong_architecture_are_blockers(self):
        data = b"MZ" + b"\0" * 260
        with patch("compact_windows_real_apps.discover",
                   side_effect=ValueError("unsupported PE")):
            report = analyze("sort", data, {}, {"reference_passed": True})
        self.assertIn("parser", report["blocking_reasons"][-1])
        with patch("compact_windows_real_apps.discover", return_value={
            "architecture": "amd64", "declared_import_profile_covered": False,
        }):
            report = analyze("sort", data, {}, {"reference_passed": True})
        self.assertIn("incomplete", report["blocking_reasons"][-1])
        with patch("compact_windows_real_apps.discover", return_value={
            "architecture": "arm64-classic", "declared_import_profile_covered": True,
        }):
            report = analyze("sort", data, {}, {"reference_passed": True})
        self.assertIn("not AMD64", report["pe_audit_rejection"])
        self.assertFalse(report["guest_execution_verified"])


if __name__ == "__main__":
    unittest.main()
