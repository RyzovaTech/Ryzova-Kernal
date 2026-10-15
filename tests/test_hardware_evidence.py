# SPDX-License-Identifier: AGPL-3.0-only
"""D0.2 source-evidence extraction regression checks."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from hardware_evidence import extract_evidence, strip_c_comments


class HardwareEvidenceTests(unittest.TestCase):
    def test_exact_pcimatch_and_wildcard_are_distinct(self):
        src = """pcimatch(p, 0x8086, 0x15c8);
pcimatch(p, 0x8086, 0);
pcimatch(p, 0, 0);
"""
        records, _ = extract_evidence("sample.c", src, "etherx550")
        self.assertEqual([r["interpretation"] for r in records],
                         ["exact-literal-probe", "vendor-only-scan", "wildcard-scan"])
        self.assertEqual(records[0]["vendor_id"], "8086")
        self.assertEqual(records[0]["device_id"], "15c8")
        self.assertIsNone(records[1]["device_id"])

    def test_scoped_vendor_switch_candidates(self):
        src = """while(pdev = pcimatch(pdev, 0x8086, 0)) {
    switch(pdev->did) {
      default: continue;
      case 0x0084:
      case 0x4230:
         break;
    }
}
"""
        matches, _ = extract_evidence("example.c", src, "etheriwl")
        candidates = [r for r in matches if r["kind"] == "vendor-scoped-switch-candidate"]
        self.assertEqual([(r["vendor_id"], r["device_id"]) for r in candidates],
                         [("8086", "0084"), ("8086", "4230")])

    def test_vendor_switch_not_inferred_without_vendor(self):
        src = """while(p = pcimatch(p, 0, 0)){
switch(p->did){ case 0x8139: break; }
}"""
        matches, _ = extract_evidence("example.c", src, "ether8139")
        self.assertFalse(any(m["kind"] == "vendor-scoped-switch-candidate" for m in matches))

    def test_comments_do_not_fake_support(self):
        src = """/* pcimatch(p, 0x9999, 0x1234); */
pcimatch(p, 0x8086, 0x15c8);
// pcimatch(p, 0x9999, 0x5555);
"""
        matches, _ = extract_evidence("example.c", src, "etherx550")
        self.assertEqual(len(matches), 1)
        self.assertEqual(strip_c_comments(src).count("\n"), src.count("\n"))

    def test_nvme_class_and_firmware_dependency(self):
        code = """if(p->ccrb != 1 || p->ccru != 8 || p->ccrp != 2)
    continue;
snprint(buf, sizeof buf, "/lib/firmware/%s", name);
fwname = "iwm-7260-17";
"""
        records, fw = extract_evidence("port/sdnvme.c", code, "sdnvme")
        self.assertEqual([m["class_code"] for m in records if m["kind"] == "pci-class-condition"],
                         ["01:08:02"])
        self.assertEqual([v["reference"] for v in fw],
                         ["/lib/firmware/%s", "iwm-7260-17"])
        self.assertTrue(all(f["redistribution_status"] == "not-reviewed" for f in fw))

    def test_unsupported_usb_ids_remain_unknown(self):
        records, fw = extract_evidence("port/usbxhcipci.c",
              "if(p->ccrb != Pcibcserial || p->ccru != Pciscusb || p->ccrp != 0x30) continue;",
              "usbxhcipci")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["class_code"], "0c:03:30")
        self.assertFalse(any("device_id" in m for m in records))
        self.assertFalse(fw)


if __name__ == "__main__":
    unittest.main()
