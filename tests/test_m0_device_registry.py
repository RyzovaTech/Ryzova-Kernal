# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed M0 candidate matcher; synthetic devices are NOT hardware support."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import m0_device_registry as m0


class M0DeviceRegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for p in ("sys/src/9/pc/etheri225.c", "sys/src/9/port/sdnvme.c"):
            target = self.root / p
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("/* synthetic test source */", encoding="utf-8")
        config = self.root / "sys/src/9/pc64/pc64"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("link\n\tetheri225 pci\nmisc\n\tsdnvme pci\n", encoding="utf-8")
        self.firmware = {"schema": m0.FW_SCHEMA, "entries": []}
        self.exact = {
            "id": "i225", "bus": "pci", "driver": "etheri225",
            "source_file": "sys/src/9/pc/etheri225.c",
            "selector": {"vendor_id": "8086", "device_id": "15f3"},
            "revision_min": 1, "revision_max": 5,
            "firmware_id": None, "evidence_level": "source-candidate", "binding_enabled": False
        }
        self.classrule = {
            "id": "nvme", "bus": "pci", "driver": "sdnvme",
            "source_file": "sys/src/9/port/sdnvme.c",
            "selector": {"class": "01", "subclass": "08", "protocol": "02"},
            "revision_min": 0, "revision_max": 255,
            "firmware_id": None, "evidence_level": "source-candidate", "binding_enabled": False
        }
        self.registry = {"schema": m0.SCHEMA, "binding_enabled": False,
                         "rules": [self.exact, self.classrule]}

    def index(self, reg=None, firmware=None):
        return m0.CandidateIndex(self.registry if reg is None else reg,
                                 self.firmware if firmware is None else firmware, self.root)

    def test_source_candidates_never_certify_or_bind(self):
        idx = self.index()
        idx.verify_pc64_configuration(self.root)
        found = idx.match("pci", 0x8086, 0x15f3, 2, 0, 0, 1)
        self.assertEqual(found["driver"], "etheri225")
        self.assertEqual(found["result"], "source-candidate")
        self.assertFalse(found["auto_bind_allowed"])
        self.assertFalse(found["hardware_verified"])
        self.assertEqual(idx.match("pci", 1, 2, 1, 8, 2, 1)["driver"], "sdnvme")
        self.assertEqual(idx.match("pci", 1, 2, 2, 0, 0, 1)["result"], "unknown")

    def test_exact_revision_precedence_and_fallback(self):
        reg = copy.deepcopy(self.registry)
        fallback = copy.deepcopy(self.classrule)
        fallback["id"] = "other-class"
        fallback["selector"] = {"class": "02", "subclass": "00"}
        reg["rules"].append(fallback)
        idx = self.index(reg)
        self.assertEqual(idx.match("pci", 0x8086, 0x15f3, 2, 0, 0, 2)["driver"], "etheri225")
        self.assertEqual(idx.match("pci", 0x8086, 0x15f3, 2, 0, 0, 7)["driver"], "sdnvme")
        with self.assertRaises(m0.RegistryError):
            idx.match("pci", 1, 1, 1, 1, 1, -1)

    def test_duplicate_ids_and_overlapping_revisions_rejected(self):
        reg = copy.deepcopy(self.registry)
        reg["rules"].append(copy.deepcopy(self.exact))
        with self.assertRaisesRegex(m0.RegistryError, "duplicate rule"):
            self.index(reg)
        reg["rules"][-1]["id"] = "overlap"
        with self.assertRaisesRegex(m0.RegistryError, "overlapping"):
            self.index(reg)
        reg["rules"][-1]["revision_min"] = 6
        reg["rules"][-1]["revision_max"] = 10
        self.index(reg)

    def test_unreviewed_firmware_requires_manifest_and_never_bundles(self):
        reg = copy.deepcopy(self.registry)
        reg["rules"][0]["firmware_id"] = "missing"
        with self.assertRaisesRegex(m0.RegistryError, "unknown firmware"):
            self.index(reg)
        fw = {"schema": m0.FW_SCHEMA, "entries": [{
            "id": "missing", "path_hint": "/lib/firmware/research-only",
            "sha256": None, "redistribution": "not-reviewed", "payload_included": False
        }]}
        self.index(reg, fw)
        fw["entries"][0]["payload_included"] = True
        with self.assertRaisesRegex(m0.RegistryError, "cannot bundle"):
            self.index(reg, fw)

    def test_reject_fabricated_certification_or_autobind(self):
        for field, value in (("evidence_level", "certified"), ("binding_enabled", True)):
            reg = copy.deepcopy(self.registry)
            reg["rules"][0][field] = value
            with self.assertRaises(m0.RegistryError):
                self.index(reg)
        reg = copy.deepcopy(self.registry)
        reg["binding_enabled"] = True
        with self.assertRaises(m0.RegistryError):
            self.index(reg)

    def test_source_traversal_and_disabled_module_rejected(self):
        reg = copy.deepcopy(self.registry)
        reg["rules"][0]["source_file"] = "../../tmp/fake"
        with self.assertRaises(m0.RegistryError):
            self.index(reg)
        idx = self.index()
        (self.root / "sys/src/9/pc64/pc64").write_text(
            "link\n#\tetheri225 pci\nmisc\n\tsdnvme pci\n", encoding="utf-8")
        with self.assertRaisesRegex(m0.RegistryError, "not active"):
            idx.verify_pc64_configuration(self.root)

    def test_duplicate_json_keys_rejected(self):
        file = self.root / "bad.json"
        file.write_text('{"rules":[],"rules":[]}', encoding="utf-8")
        with self.assertRaisesRegex(m0.RegistryError, "duplicate JSON key"):
            m0.read_json(file)

    def test_synthetic_10k_rule_index_not_hardware_count(self):
        reg = copy.deepcopy(self.registry)
        for i in range(10000):
            r = copy.deepcopy(self.exact)
            r["id"] = "fixture-%05d" % i
            r["selector"]["vendor_id"] = "%04x" % (i // 100)
            r["selector"]["device_id"] = "%04x" % (i % 100)
            reg["rules"].append(r)
        idx = self.index(reg)
        self.assertEqual(len(idx.rules), 10002)
        for i in range(0, 10000, 499):
            x = idx.match("pci", i // 100, i % 100, 0, 0, 0, 2)
            self.assertTrue(x["rule_id"].startswith("fixture-"))
            self.assertFalse(x["hardware_verified"])


if __name__ == "__main__":
    unittest.main()
