# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the AMD64 pc64 configuration source inventory."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import driver_inventory


EXAMPLE = """# pc64 example
dev
    root
    pnp pci
#\tlpt
    sd
link
    etheri225 pci ethermii
#\tetherold pci
# should be removed once obsolete
    usbxhcipci pci usbxhci
misc
    sdnvme pci
    vgasoft =cur swcursor
#\tvganvidia +cur
ip
    tcp
port
    int cpuserver = 0;
bootdir
    /amd64/bin/paqfs
"""


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for d, file in [
            ("pc", "etheri225.c"),
            ("pc", "vgasoft.c"),
            ("port", "devroot.c"),
            ("port", "sdnvme.c"),
            ("port", "usbxhcipci.c"),
            ("ip", "tcp.c"),
        ]:
            dest = self.root / "sys/src/9" / d / file
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("/* fixture */", encoding="utf-8")

    def test_counts_enabled_disabled_and_sections(self):
        result = driver_inventory.inventory(EXAMPLE, self.root)
        modules = {x["module"]: x for x in result["entries"]}
        self.assertEqual(len(modules), 10)
        self.assertFalse(modules["lpt"]["enabled"])
        self.assertFalse(modules["etherold"]["enabled"])
        self.assertFalse(modules["vganvidia"]["enabled"])
        self.assertTrue(modules["etheri225"]["enabled"])
        self.assertNotIn("should", modules)
        self.assertNotIn("int", modules)
        self.assertNotIn("amd64", modules)
        self.assertEqual(result["counts"]["disabled"], 3)
        self.assertEqual(result["counts"]["enabled"], 7)
        self.assertEqual(modules["etheri225"]["section"], "link")

    def test_source_paths_are_verified_on_disk_not_inferred(self):
        modules = {x["module"]: x for x in
                   driver_inventory.inventory(EXAMPLE, self.root)["entries"]}
        self.assertEqual(modules["root"]["source_file"], "sys/src/9/port/devroot.c")
        self.assertEqual(modules["etheri225"]["source_file"], "sys/src/9/pc/etheri225.c")
        self.assertEqual(modules["sdnvme"]["source_file"], "sys/src/9/port/sdnvme.c")
        self.assertIsNone(modules["etherold"]["source_file"])
        self.assertFalse(modules["etherold"]["source_present"])

    def test_never_claim_device_compatibility(self):
        result = driver_inventory.inventory(EXAMPLE, self.root)
        for module in result["entries"]:
            self.assertEqual(module["pci_usb_ids"], [])
            self.assertEqual(module["device_ids_review"], "not-reviewed")
            self.assertEqual(module["firmware_review"], "not-reviewed")
            self.assertEqual(module["physical_hardware_status"], "unverified")
            self.assertEqual(module["test_evidence"], [])
        self.assertIn("NOT hardware compatibility", result["meaning"])

    def test_deterministic_result_and_hash(self):
        a = driver_inventory.inventory(EXAMPLE, self.root)
        b = driver_inventory.inventory(EXAMPLE, self.root)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(a["config_sha256"], hashlib.sha256(EXAMPLE.encode()).hexdigest())
        self.assertEqual(a["schema"], "ryzova-driver-inventory/v1")

    def test_section_boundaries_and_enabled_inline_comment(self):
        sample = """link
    etheri225 pci # inline remark
# remark text
misc
    sdnvme pci
port
    devfake
"""
        entries = driver_inventory.inventory(sample, self.root)["entries"]
        self.assertEqual([x["module"] for x in entries], ["etheri225", "sdnvme"])
        self.assertEqual(entries[0]["arguments"], ["pci"])


if __name__ == "__main__":
    unittest.main()
