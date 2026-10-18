# SPDX-License-Identifier: AGPL-3.0-only
"""M2 chipset family audit and adversarial metadata checks."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from m0_device_registry import RegistryError, read_json, CandidateIndex
from m0_native_rules import generate, OUTPUT
from m2_chipset_audit import audit


class M2ChipsetTests(unittest.TestCase):
    def setUp(self):
        self.manifest = read_json(ROOT / "ryzova/drivers/m2-chipset-families.json")
        self.registry = read_json(ROOT / "ryzova/drivers/m0-device-registry.json")
        self.firmware = read_json(ROOT / "ryzova/drivers/m0-firmware-manifest.json")

    def run_audit(self, manifest=None, registry=None, firmware=None):
        return audit(manifest or self.manifest, registry or self.registry,
                     firmware or self.firmware, ROOT)

    def test_independently_sourced_chipset_families(self):
        report = self.run_audit()
        self.assertEqual(report["vendor_families"], ["amd", "intel", "realtek"])
        self.assertEqual(report["source_candidate_ids"], 12)
        self.assertEqual(report["physical_verified_models"], 0)
        self.assertEqual(report["certified_models"], 0)
        self.assertEqual(report["release_gate"], "blocked")
        self.assertFalse(report["auto_bind_allowed"])
        self.assertTrue(report["legacy_track_present"])
        self.assertTrue(report["modern_track_present"])
        self.assertEqual(set(report["firmware_review_blocked"]),
                         {"m2-intel-wpi-4222-candidate", "m2-intel-wpi-4227-candidate"})

    def test_deterministic_native_table_and_legacy_config(self):
        self.assertEqual(generate(ROOT), (ROOT / OUTPUT).read_text(encoding="utf-8"))
        idx = CandidateIndex(self.registry, self.firmware, ROOT)
        idx.verify_pc64_configuration(ROOT)
        for row in self.manifest["entries"]:
            result = idx.match("pci", int(row["vendor_id"], 16),
                               int(row["device_id"], 16), 2, 0, 0, 0)
            self.assertEqual(result["rule_id"], "m2-"+row["id"]+"-candidate")
            self.assertFalse(result["hardware_verified"])
            self.assertFalse(result["auto_bind_allowed"])

    def test_reject_false_certification_and_device_claims(self):
        for field in ("certified", "auto_bind_allowed"):
            bad = copy.deepcopy(self.manifest)
            bad["entries"][0][field] = True
            with self.assertRaises(RegistryError):
                self.run_audit(manifest=bad)
        bad = copy.deepcopy(self.registry)
        rid = "m2-intel-e1000-82540em-candidate"
        next(x for x in bad["rules"] if x["id"] == rid)["binding_enabled"] = True
        with self.assertRaises(RegistryError):
            self.run_audit(registry=bad)

    def test_reject_vendor_spoofing_invalid_source_and_registry_drift(self):
        bad = copy.deepcopy(self.manifest)
        bad["entries"][0]["vendor_id"] = "10ec"
        with self.assertRaises(RegistryError):
            self.run_audit(manifest=bad)
        bad = copy.deepcopy(self.manifest)
        bad["entries"][0]["source_anchor"] = "pcimatch(p, 0x8086, 0x100e)"
        with self.assertRaises(RegistryError):
            self.run_audit(manifest=bad)
        bad = copy.deepcopy(self.registry)
        rid = "m2-intel-x550-15c8-candidate"
        next(x for x in bad["rules"] if x["id"] == rid)["driver"] = "etherigbe"
        with self.assertRaises(RegistryError):
            self.run_audit(registry=bad)

    def test_firmware_rights_never_self_approve(self):
        bad = copy.deepcopy(self.firmware)
        bad["entries"][0]["payload_included"] = True
        with self.assertRaises(RegistryError):
            self.run_audit(firmware=bad)
        bad = copy.deepcopy(self.manifest)
        bad["entries"][0]["firmware_id"] = "missing-license"
        with self.assertRaises(RegistryError):
            self.run_audit(manifest=bad)

    def test_chipset_expansion_preserves_old_and_new_pcs(self):
        bad = copy.deepcopy(self.manifest)
        bad["tracks"] = ["modern-amd64"]
        with self.assertRaises(RegistryError):
            self.run_audit(manifest=bad)
        bad = copy.deepcopy(self.manifest)
        bad["entries"] = [r for r in bad["entries"] if r["track"] != "legacy-amd64"]
        with self.assertRaises(RegistryError):
            self.run_audit(manifest=bad)


if __name__ == "__main__":
    unittest.main()
