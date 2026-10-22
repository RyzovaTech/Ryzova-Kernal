# SPDX-License-Identifier: AGPL-3.0-only
"""Source guards for Intel/Ralink firmware allocation limits. No radio testing."""
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class WifiFirmwareGuards(unittest.TestCase):
    def test_firmware_size_cap_precedes_allocation(self):
        for name in ("sys/src/9/port/etheriwl.c", "sys/src/9/pc/etherwpi.c", "sys/src/9/pc/etherrt2860.c"):
            with self.subTest(name=name):
                s=(ROOT / name).read_text()
                f=s[s.index("readfirmware("):]
                self.assertIn("d.length <= 0 || d.length > 16*1024*1024", f)
                self.assertLess(f.index("d.length <= 0"), f.index("smalloc("))
    def test_ralink_firmware_container_alloc_guarded(self):
        s=(ROOT / "sys/src/9/pc/etherrt2860.c").read_text()
        a=s.index("fw = malloc(sizeof(*fw));")
        b=s.index("fw->size = d.length;",a)
        self.assertIn("if(fw == nil)",s[a:b])

if __name__ == "__main__":
    unittest.main()
