# SPDX-License-Identifier: AGPL-3.0-only
"""M5 ARM64 ECAM linkage and server/legacy readiness audit."""
import copy
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from m0_device_registry import RegistryError, read_json
from m5_platform_audit import audit

class M5ArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.m=read_json(ROOT/"ryzova/drivers/m5-platform-matrix.json")

    def test_arm64_and_servers_are_source_only(self):
        r=audit(ROOT,self.m)
        self.assertEqual(r["source_profile_count"],3)
        self.assertFalse(r["arm64_native_boot_confirmed"])
        self.assertEqual(r["newly_certified_models"],0)
        self.assertFalse(r["auto_binding"])
        self.assertEqual([p["profile"] for p in r["profiles"]],
                         ["arm64-qemu-server","amd64-server","legacy-amd64"])
        self.assertFalse(r["profiles"][0]["boot_verified"])
        self.assertTrue(r["profiles"][1]["boot_verified"])
        self.assertTrue(r["profiles"][2]["boot_verified"])
        self.assertTrue(all(not p["physical_verified"] for p in r["profiles"]))

    def test_arm64_pci_ecam_fail_closed(self):
        source=(ROOT/"sys/src/9/arm64/pciqemu.c").read_text()
        for required in ('#include "m5ecam.h"',
                         "m5ecamoffset(BUSBNO(tbdf), BUSDNO(tbdf), BUSFNO(tbdf),",
                         "BUSTYPE(tbdf) != BusPCI",
                         "if(ecam == nil)",
                         "if(pcimaxdno < 1 || pcimaxdno > 32)"):
            self.assertIn(required,source)
        self.assertIn("m5ecam.$O", (ROOT/"sys/src/9/arm64/mkfile").read_text())
        self.assertLess(source.index("m5ecamoffset("), source.index("return ecam + off;"))
        self.assertEqual(source.count("cfgaddr(tbdf, rno & ~3, 4)"),1)
        self.assertEqual(source.count("cfgaddr(tbdf, rno & ~1, 2)"),1)
        self.assertEqual(source.count("cfgaddr(tbdf, rno, 1)"),1)

    def test_physical_claims_and_false_arm64_boot_blocked(self):
        for field,val in (("certified_models",1),("automatic_cross_arch_driver_bind",True),
                          ("release_gate","green")):
            changed=copy.deepcopy(self.m)
            changed[field]=val
            with self.assertRaises(RegistryError): audit(ROOT,changed)
        for field in ("native_compilation_verified","boot_verified","physical_verified"):
            changed=copy.deepcopy(self.m)
            changed["profiles"][0][field]=True
            with self.assertRaises(RegistryError): audit(ROOT,changed)
        changed=copy.deepcopy(self.m)
        changed["profiles"][1]["physical_verified"]=True
        with self.assertRaises(RegistryError): audit(ROOT,changed)

    def test_legacy_never_removed(self):
        changed=copy.deepcopy(self.m)
        changed["profiles"].pop()
        with self.assertRaises(RegistryError): audit(ROOT,changed)
        changed=copy.deepcopy(self.m)
        changed["profiles"][2]["required_link_drivers"].remove("usbehci")
        with self.assertRaises(RegistryError): audit(ROOT,changed)
        changed=copy.deepcopy(self.m)
        changed["profiles"][0]["required_link_drivers"].append("sdnvme")
        with self.assertRaises(RegistryError): audit(ROOT,changed)

    def test_source_and_evidence_rules(self):
        arm=self.m["profiles"][0]
        for name in ("arm64-native-compiler-link","aarch64-qemu-boot",
                     "ecam-out-of-range-negative-test","virtio-storage-integrity"):
            self.assertIn(name,arm["evidence_needed"])
        for p in self.m["profiles"]:
            self.assertGreaterEqual(len(p["evidence_needed"]),5)

if __name__=="__main__":
    unittest.main()
