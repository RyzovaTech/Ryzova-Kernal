# SPDX-License-Identifier: AGPL-3.0-only
"""M1 release gates cannot certify source-level candidates."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from m0_device_registry import RegistryError, read_json
from m1_usb_qualification import evaluate

class M1Qualifications(unittest.TestCase):
    def setUp(self):
        self.plan = read_json(ROOT/"ryzova/drivers/m1-usb-qualification.json")
        self.registry = read_json(ROOT/"ryzova/drivers/m0-device-registry.json")
        self.fw = read_json(ROOT/"ryzova/drivers/m0-firmware-manifest.json")

    def run_eval(self, plan=None):
        return evaluate(self.plan if plan is None else plan,
                        self.registry, self.fw, ROOT)

    def test_m1_classes_blocked_and_modern_legacy_retained(self):
        result=self.run_eval()
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["certified_models"],0)
        self.assertEqual(result["class_source_candidates"],7)
        self.assertEqual(result["platforms"],["modern-amd64","legacy-amd64"])
        self.assertFalse(result["auto_bind_allowed"])

    def test_malformed_certification_rejected(self):
        plan=copy.deepcopy(self.plan)
        plan["classes"][0]["certified"]=True
        with self.assertRaises(RegistryError): self.run_eval(plan)
        plan=copy.deepcopy(self.plan)
        plan["classes"].pop()
        with self.assertRaises(RegistryError): self.run_eval(plan)
        plan=copy.deepcopy(self.plan)
        plan["platforms"].remove("legacy-amd64")
        with self.assertRaises(RegistryError): self.run_eval(plan)

    def test_unmatched_driver_metadata_rejected(self):
        plan=copy.deepcopy(self.plan)
        plan["classes"][0]["selectors"]=["pci-ahci-class-candidate"]
        with self.assertRaises(RegistryError): self.run_eval(plan)


if __name__ == "__main__":
    unittest.main()
