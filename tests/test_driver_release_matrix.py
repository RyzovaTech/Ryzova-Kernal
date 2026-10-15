# SPDX-License-Identifier: AGPL-3.0-only
"""D0.3-D6 source evidence and fail-closed release safety tests."""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from driver_release_matrix import build_matrix, evaluate_release, validate_evidence


def blank():
    return {
        "schema": "ryzova-physical-driver-tests/v1",
        "test_records": [],
        "maintainer_approval": None,
        "license_clearance": False,
        "independent_lab_review": None,
    }


class MatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.matrix = build_matrix(cls.root)

    def test_source_inventory_matches_review_scope(self):
        m = self.matrix
        self.assertEqual(m["counts"]["drivers_inspected"], 15)
        self.assertEqual(m["counts"]["real_hardware_verified"], 0)
        self.assertTrue(m["counts"]["source_probe_records"] >= 10)
        self.assertTrue(m["counts"]["class_selector_records"] >= 3)
        self.assertTrue(m["source_config_sha256"])
        self.assertEqual(m["schema"], "ryzova-driver-source-matrix/v1")

    def test_specific_probe_evidence_not_claimed_verified(self):
        rows = self.matrix["device_probe_evidence"]
        self.assertTrue(any(r["driver"] == "etheri225" and
                            r["vendor_id"] == "8086" and r["device_id"] == "15f3"
                            for r in rows))
        self.assertTrue(any(r["driver"] == "sdnvme" and r["pci_class"] == "01:08:02"
                            for r in rows))
        self.assertTrue(any(r["driver"] == "usbxhcipci" and r["pci_class"] == "0c:03:30"
                            for r in rows))
        self.assertTrue(all(r["verified"] is False for r in rows))

    def test_firmware_evidence_never_implies_rights(self):
        fw = self.matrix["firmware_evidence"]
        self.assertTrue(any(r["driver"] == "etheriwl" for r in fw))
        self.assertTrue(all(r["redistribution_rights"] == "not-reviewed" for r in fw))
        self.assertTrue(all(r["payload_included_by_audit"] is False for r in fw))

    def test_deterministic_order(self):
        a = json.dumps(self.matrix, sort_keys=True)
        b = json.dumps(build_matrix(self.root), sort_keys=True)
        self.assertEqual(a, b)

    def test_physical_evidence_empty_is_valid_but_release_blocked(self):
        p = blank()
        self.assertEqual(validate_evidence(p), [])
        result = evaluate_release(self.matrix, p)
        self.assertEqual(result["gate"], "blocked")
        self.assertFalse(result["auto_release_allowed"])
        self.assertIn("no-physical-hardware-test-records", result["blockers"])
        self.assertIn("binary-license-clearance-missing", result["blockers"])

    def test_unsubstantiated_hardware_claim_is_rejected(self):
        p = blank()
        p["test_records"] = [{"driver": "etheri225", "vendor_id": "8086",
                               "device_id": "15f3", "tests": {"boot": True}}]
        self.assertTrue(validate_evidence(p))
        self.assertIn("physical-evidence-schema-errors",
                      evaluate_release(self.matrix, p)["blockers"])

    def test_not_autoreleased_even_with_manual_flags(self):
        p = blank()
        p["maintainer_approval"] = "someone"
        p["license_clearance"] = True
        p["independent_lab_review"] = "someone"
        result = evaluate_release(self.matrix, p)
        self.assertEqual(result["gate"], "blocked")
        self.assertIn("human-release-authorization-required", result["blockers"])


if __name__ == "__main__":
    unittest.main()
