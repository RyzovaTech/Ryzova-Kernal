# SPDX-License-Identifier: AGPL-3.0-only
"""Source regression for rejecting invalid PCI BAR0 on Intel i225/i226."""
import re
import unittest
from pathlib import Path

S = (Path(__file__).resolve().parents[1] / "sys/src/9/pc/etheri225.c")

class I225BarGuards(unittest.TestCase):
    def test_bar_validation_precedes_mapping_and_allocation(self):
        c = S.read_text(encoding="utf-8")
        f = c[c.index("i225pci(void)"):c.index("i225pnp(Ether *e)")]
        self.assertRegex(f, r"p->mem\[0\]\.size\s*==\s*0")
        self.assertIn("(p->mem[0].bar & ~0xFULL) == 0", f)
        self.assertLess(f.index("p->mem[0].size == 0"), f.index("vmap(c->port"))

if __name__ == "__main__":
    unittest.main()
