# SPDX-License-Identifier: AGPL-3.0-only
"""M1 host-regression checks; NOT a USB compatibility certification."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from m0_device_registry import CandidateIndex, read_json
from m0_native_rules import generate, OUTPUT


class M1UsbFamilySource(unittest.TestCase):
    def test_shared_library_is_built(self):
        s=(ROOT/"sys/src/cmd/nusb/lib/mkfile").read_text()
        self.assertIn("m1class.$O",s)
        self.assertIn("m1class.h",s)

    def test_hid_and_device_descriptors_are_checked_before_use(self):
        k=(ROOT/"sys/src/cmd/nusb/kb/kb.c").read_text()
        p=(ROOT/"sys/src/cmd/nusb/lib/parse.c").read_text()
        self.assertIn("m1hidpacketvalid(f->ep->maxpkt, sizeof(p.p))",k)
        self.assertLess(p.index("m1usbdevdescvalid(b, n)"),p.index("dd = (DDev*)b;"))
        self.assertLess(p.index("n < Dconflen"),p.index("dc = (DConf*)b;"))

    def test_shared_usb_parser_bounds_endpoints_and_config_length(self):
        p=(ROOT/"sys/src/cmd/nusb/lib/parse.c").read_text()
        self.assertIn("if((ep->maxpkt & 0x7FF) == 0)",p)
        self.assertIn("if(len < 2)",p)
        self.assertIn("if(l < Dconflen || n < l)",p)
        self.assertIn("n = l - Dconflen;",p)
        self.assertLess(p.index("if(l < Dconflen || n < l)"),p.index("n = l - Dconflen;"))

    def test_storage_rejects_overflow_and_invalid_bot_status(self):
        s=(ROOT/"sys/src/cmd/nusb/disk/disk.c").read_text()
        self.assertLess(s.index("m1diskcapacityvalid(lun->blocks, lun->lbsize)"),
                        s.index("lun->blocks++;"))
        self.assertIn("if(++mismatches >= 3)",s)
        self.assertIn("if(cmd->count < 1 || cmd->count > 16 || data->count < 0)",s)
        self.assertNotIn("assert(cmd->count <= sizeof(cbw.command))",s)

    def test_audio_rejects_short_frequencies(self):
        s=(ROOT/"sys/src/cmd/nusb/audio/audio.c").read_text()
        self.assertIn("m1uac1freqvalid(b, dd->data.bLength)",s)

    def test_cdc_rejects_invalid_mac_and_zero_maxpkt(self):
        s=(ROOT/"sys/src/cmd/nusb/ether/cdc.c").read_text()
        self.assertIn("dd->data.bLength >= 4",s)
        self.assertIn("m1cdcmacvalid(mac, strlen(mac))",s)
        self.assertIn("ep->maxpkt > 0",s)

    def test_m1_usb_families_stay_source_only(self):
        raw=read_json(ROOT/"ryzova/drivers/m0-device-registry.json")
        fwid=read_json(ROOT/"ryzova/drivers/m0-firmware-manifest.json")
        idx=CandidateIndex(raw,fwid,ROOT)
        idx.verify_pc64_configuration(ROOT)
        expect={"usb-hid-boot-keyboard-candidate","usb-hid-boot-pointer-candidate",
                "usb-mass-storage-bot-candidate","usb-mass-storage-uas-candidate",
                "usb-audio1-stream-candidate","usb-audio2-stream-candidate",
                "usb-cdc-ethernet-candidate"}
        rules=[r for r in raw["rules"] if r["id"] in expect]
        self.assertEqual({r["id"] for r in rules},expect)
        self.assertTrue(all(r["evidence_level"]=="source-candidate" and
                            r["binding_enabled"] is False for r in rules))
        self.assertEqual(generate(ROOT),(ROOT/OUTPUT).read_text()) # no native PCI drift

    def test_class_families_match_only_precise_protocol(self):
        raw=read_json(ROOT/"ryzova/drivers/m0-device-registry.json")
        idx=CandidateIndex(raw,read_json(ROOT/"ryzova/drivers/m0-firmware-manifest.json"),ROOT)
        for code,sub,proto,driver in ((3,1,1,"kb"),(3,1,2,"kb"),
                                      (8,6,0x50,"disk"),(8,6,0x62,"disk"),
                                      (1,2,0,"audio"),(1,2,0x20,"audio"),
                                      (2,6,0,"ether")):
            result=idx.match("usb",0x1234,0x5678,code,sub,proto,0x100)
            self.assertEqual(result["driver"],driver)
            self.assertFalse(result["auto_bind_allowed"])
            self.assertFalse(result["hardware_verified"])
        self.assertEqual(idx.match("usb",1,2,8,6,0x99,1)["result"],"unknown")


if __name__=="__main__":
    unittest.main()
