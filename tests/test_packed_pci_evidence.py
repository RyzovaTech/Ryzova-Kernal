# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from packed_pci_evidence import packed_pci_candidates


class PackedIdsTests(unittest.TestCase):
    def test_literal_and_symbolic_vendor_device_order(self):
        code = """
enum {
    Rtl8168b = (0x8168<<16)|0x10EC,
};
void probe(void){
    while(p = pcimatch(p, 0, 0)) {
        switch(i = ((p->did<<16)|p->vid)){
          case Rtl8168b: break;
          case (0xC107<<16)|0x1259: break;
        }
    }
}
"""
        rows = packed_pci_candidates(code, "pc/ether8169.c")
        self.assertEqual([(r["vendor_id"], r["device_id"]) for r in rows],
                         [("10ec", "8168"), ("1259", "c107")])

    def test_no_claim_for_declared_but_unreferenced_enum(self):
        code = """
enum { A = (0x1000<<16)|0x8086, B = (0x1004<<16)|0x8086, };
switch((p->did<<16)|p->vid) {
    case B: break;
}
"""
        # The parser anchors at the beginning of a declaration line.
        # Inline enum declarations are deliberately not mapped.
        self.assertFalse(packed_pci_candidates(code, "pc/etherigbe.c"))

    def test_comments_and_unrelated_switches_excluded(self):
        code = """
/* case (0x1234<<16)|0x10ec: */
switch(p->did){ case (0x8168<<16)|0x10ec: break; }
"""
        self.assertEqual(packed_pci_candidates(code, "fake.c"), [])

    def test_real_source_packed_cases(self):
        root = Path(__file__).resolve().parents[1]
        e = packed_pci_candidates(
            (root / "sys/src/9/pc/ether8169.c").read_text(encoding="utf-8"),
            "sys/src/9/pc/ether8169.c")
        i = packed_pci_candidates(
            (root / "sys/src/9/pc/etherigbe.c").read_text(encoding="utf-8"),
            "sys/src/9/pc/etherigbe.c")
        self.assertTrue(any(r["vendor_id"] == "10ec" and r["device_id"] == "8168" for r in e))
        self.assertTrue(any(r["vendor_id"] == "8086" and r["device_id"] == "1004" for r in i))
        self.assertGreaterEqual(len(e), 7)
        self.assertGreaterEqual(len(i), 15)
        self.assertEqual(len({(r["vendor_id"], r["device_id"]) for r in e}), len(e))


if __name__ == "__main__":
    unittest.main()
