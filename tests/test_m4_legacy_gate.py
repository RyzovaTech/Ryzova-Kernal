# SPDX-License-Identifier: AGPL-3.0-only
"""M4 low-RAM QEMU configuration and release gate guardrail tests."""
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))

from m0_device_registry import RegistryError, read_json
from m2_qemu_probe import legacy_memory_cmd
from m4_legacy_gate import audit


class M4OldPCReleaseTest(unittest.TestCase):
    def setUp(self):
        self.m=read_json(ROOT/"ryzova/drivers/m4-legacy-qualification.json")

    def test_old_and_new_platforms_not_dropped(self):
        report=audit(ROOT,self.m)
        self.assertEqual(report["gate"],"blocked-pending-real-hardware")
        self.assertEqual(report["verified_physical_models"],0)
        self.assertEqual(report["certified_models"],0)
        self.assertEqual(report["class_families_tracked"],4)
        self.assertEqual(report["virtual_legacy_memory_mib"],384)
        self.assertFalse(report["auto_bind_allowed"])
        self.assertFalse(report["real_legacy_pcs_qualified"])

    def test_fake_certification_and_legacy_removal_refused(self):
        for field,value in (("release_approval",True),("hardware_models_certified",1)):
            x=copy.deepcopy(self.m)
            x[field]=value
            with self.assertRaises(RegistryError): audit(ROOT,x)
        x=copy.deepcopy(self.m)
        x["families"][0]["physical_verified"]=True
        with self.assertRaises(RegistryError): audit(ROOT,x)
        x=copy.deepcopy(self.m)
        x["platforms"]=["modern-amd64"]
        with self.assertRaises(RegistryError): audit(ROOT,x)
        x=copy.deepcopy(self.m)
        x["families"].pop()
        with self.assertRaises(RegistryError): audit(ROOT,x)

    def test_usb2_and_sata_legacy_release_evidence_still_required(self):
        ids={x["id"]:x for x in self.m["families"]}
        self.assertIn("disk-transfer-integrity",ids["legacy-usb-ehci"]["required_tests"])
        self.assertIn("read-write-integrity",ids["legacy-sata-ahci"]["required_tests"])
        bad=copy.deepcopy(self.m)
        bad["families"][0]["pci_candidate"]="m2-intel-x550-15c8-candidate"
        with self.assertRaises(RegistryError): audit(ROOT,bad)

    def test_qemu_ram_override_preserves_old_boot_disk_and_nics(self):
        cmd=["qemu-system-x86_64","-m","2048","-drive","file=disk.qcow2",
             "-device","pcnet","-device","rtl8139"]
        new=legacy_memory_cmd(cmd,384)
        self.assertEqual(new[2],"384")
        self.assertEqual(new.count("-m"),1)
        self.assertEqual(new[3:],cmd[3:])
        self.assertEqual(cmd[2],"2048")
        for mem in (-1,0,32,4097,True,"384"):
            with self.assertRaises(ValueError): legacy_memory_cmd(cmd,mem)
        with self.assertRaises(ValueError): legacy_memory_cmd(["qemu","-m","2048","-m","384"],384)

    def test_low_memory_boot_remains_isolated_from_main_network_tests(self):
        s=(ROOT/"scripts/phase3-native-build.py").read_text()
        self.assertIn("m4_legacy_enabled",s)
        self.assertIn("memory_mib=384 if m4_legacy_enabled else None",s)
        self.assertIn("fresh_cmd = list(cmd)",s)
        self.assertIn("second=subprocess.Popen(fresh_cmd",s)
        self.assertNotIn('m4_legacy_enabled and second=subprocess.Popen',s)


if __name__=="__main__":
    unittest.main()
