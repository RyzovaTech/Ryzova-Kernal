# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic M0.2-M0.5 regression; observations are NOT real device support."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import m0_device_registry as reg
import m0_discovery as discovery
import m0_safety_gate as safety
import m0_qualification as qual


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="ascii")


class PhasesTwoToFive(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sysfs = self.root / "sysfs"
        self.sysfs.mkdir()
        put(self.root / "sys/src/9/pc/etheri225.c", "/* fixture */")
        put(self.root / "sys/src/cmd/nusb/bt/bt.c", "/* fixture */")
        put(self.root / "sys/src/9/pc64/pc64", "link\n\tetheri225 pci\n")
        self.registry = {
            "schema": reg.SCHEMA, "binding_enabled": False,
            "rules": [
                dict(id="i225", bus="pci", driver="etheri225",
                     source_file="sys/src/9/pc/etheri225.c",
                     selector={"vendor_id": "8086", "device_id": "15f3"},
                     revision_min=0, revision_max=255, firmware_id=None,
                     evidence_level="source-candidate", binding_enabled=False),
                dict(id="bt-hci", bus="usb", driver="bt",
                     source_file="sys/src/cmd/nusb/bt/bt.c",
                     selector={"class": "e0", "subclass": "01", "protocol": "01"},
                     revision_min=0, revision_max=65535, firmware_id=None,
                     evidence_level="source-candidate", binding_enabled=False),
            ]}
        self.firmware = {"schema": reg.FW_SCHEMA, "entries": []}
        self.index = reg.CandidateIndex(self.registry, self.firmware, self.root)
        self.index.verify_pc64_configuration(self.root)
        pci = self.sysfs / "bus/pci/devices/0000:00:14.0"
        for n, v in [("vendor", "0x8086"), ("device", "0x15f3"),
                     ("class", "0x020000"), ("revision", "0x01")]:
            put(pci / n, v + "\n")
        usb = self.sysfs / "bus/usb/devices/1-3"
        for n, v in [("idVendor", "1234"), ("idProduct", "5678"),
                     ("bcdDevice", "0100"), ("bDeviceClass", "00"),
                     ("bDeviceSubClass", "00"), ("bDeviceProtocol", "00")]:
            put(usb / n, v + "\n")
        iface = self.sysfs / "bus/usb/devices/1-3:1.0"
        for n, v in [("bInterfaceClass", "e0"), ("bInterfaceSubClass", "01"),
                     ("bInterfaceProtocol", "01")]:
            put(iface / n, v + "\n")
        self.safetycontract = {
            "schema": safety.SCHEMA, "policy": "fail-closed-source-only",
            "required_checks": list(safety.NEEDED),
            "families": [{"driver": "etheri225", "bus": "pci",
                          "checks": {s: "unverified" for s in safety.NEEDED}}]
        }
        self.physical = {"schema": "ryzova-physical-driver-tests/v1",
                         "test_records": [], "maintainer_approval": None,
                         "license_clearance": False, "independent_lab_review": None}
        self.plan = {"schema": qual.SCHEMA, "release_policy": "human-evidence-required",
                     "platforms": [
                         dict(id=track, profile=track, description=track,
                              min_physical_devices=2,
                              mandatory_tests=list(qual.REQUIRED_TESTS),
                              additional_tests=["pci", "usb", "storage", "network"],
                              qualified=False) for track in qual.REQUIRED_TRACKS]}

    def test_discovery_matches_pci_and_usb_interface_not_just_device(self):
        r = discovery.discovery(self.sysfs, self.index)
        self.assertEqual(r["device_observations"], 3)
        self.assertEqual(r["source_candidates"], 2)
        self.assertEqual(r["newly_verified_hardware_models"], 0)
        self.assertFalse(r["auto_bind_allowed"])
        self.assertEqual({d["locator"] for d in r["devices"]
                          if d["source_candidate"]["result"] == "source-candidate"},
                         {"0000:00:14.0", "1-3:1.0"})
        self.assertEqual(r["observations_sha256"],
                         discovery.discovery(self.sysfs, self.index)["observations_sha256"])
        self.assertTrue(all(d["hardware_verified"] is False for d in r["devices"]))

    def test_discovery_rejects_bogus_sysfs_data_and_escape_symlink(self):
        put(self.sysfs / "bus/pci/devices/0000:00:14.0/revision", "FFFFFFFFFF")
        with self.assertRaises(reg.RegistryError):
            discovery.discovery(self.sysfs, self.index)
        put(self.sysfs / "bus/pci/devices/0000:00:14.0/revision", "01")
        outside = self.root / "outside"
        outside.mkdir()
        (self.sysfs / "bus/usb/devices/1-5").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(reg.RegistryError):
            discovery.discovery(self.sysfs, self.index)

    def test_firmware_dma_irq_checks_block_release(self):
        r = safety.audit(self.safetycontract, self.firmware, self.physical)
        self.assertEqual(r["gate"], "blocked")
        self.assertEqual(r["unverified_contract_checks"], len(safety.NEEDED))
        self.assertFalse(r["auto_release_allowed"])
        changed = copy.deepcopy(self.safetycontract)
        changed["families"][0]["checks"]["dma-mapping"] = "certified"
        with self.assertRaises(reg.RegistryError):
            safety.audit(changed, self.firmware, self.physical)
        fake = copy.deepcopy(self.physical)
        fake["test_records"].append({"tests": {"boot": True}})
        self.assertEqual(safety.audit(self.safetycontract, self.firmware, fake)["gate"], "blocked")

    def test_unreviewed_firmware_is_reported_as_blocked(self):
        fw = {"schema": reg.FW_SCHEMA, "entries": [{
            "id": "fw-example", "path_hint": "/lib/firmware/fw-example",
            "sha256": None, "redistribution": "not-reviewed", "payload_included": False}]}
        report = safety.audit(self.safetycontract, fw, self.physical)
        self.assertIn("firmware-rights-or-hash-not-cleared", report["release_blockers"])

    def test_modern_and_legacy_evidence_both_required(self):
        result = qual.evaluate(self.plan, self.physical)
        self.assertEqual([x["id"] for x in result["platforms"]],
                         list(qual.REQUIRED_TRACKS))
        self.assertEqual(result["certified_hardware_models"], 0)
        self.assertTrue(all(x["qualification"] == "blocked" for x in result["platforms"]))
        fake = copy.deepcopy(self.physical)
        fake["test_records"].append({"device_id": "0"})
        self.assertEqual(qual.evaluate(self.plan, fake)["certified_hardware_models"], 0)
        changed = copy.deepcopy(self.plan)
        changed["platforms"].pop()
        with self.assertRaises(reg.RegistryError):
            qual.evaluate(changed, self.physical)
        changed = copy.deepcopy(self.plan)
        changed["platforms"][1]["qualified"] = True
        with self.assertRaises(reg.RegistryError):
            qual.evaluate(changed, self.physical)


if __name__ == "__main__":
    unittest.main()
