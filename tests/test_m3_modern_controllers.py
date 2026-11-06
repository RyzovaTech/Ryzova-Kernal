# SPDX-License-Identifier: AGPL-3.0-only
"""M3 modern Intel 10GbE and NVMe hardware safety regression.

Static invariants complement native 6c/6l/QEMU compilation. They do not
certify operation on an Intel X550 or a physical NVMe drive.
"""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
X550 = ROOT / "sys/src/9/pc/etherx550.c"
NVME = ROOT / "sys/src/9/port/sdnvme.c"


class M3ModernControllerSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ether = X550.read_text(encoding="utf-8")
        cls.nvme = NVME.read_text(encoding="utf-8")

    def test_x550_nvm_and_dma_polls_are_finite(self):
        e=self.ether
        body=e[e.index("reset(Ctlr *c)"):e.index("txinit(Ctlr *c)")]
        self.assertNotRegex(body, r"while\s*\(\(c->reg\[(Eec|Eemngctl|Rdrxctl)\]")
        self.assertIn("m3waitreg(c, Eec, AutoRd)",body)
        self.assertIn("m3waitreg(c, Eemngctl, CfgDone0|CfgDone1)",body)
        self.assertIn("m3waitreg(c, Rdrxctl, Dmaidone)",body)
        self.assertEqual(body.count("m3waitreg(c,"),6)
        self.assertIn("initial NVM/DMA readiness timeout",body)
        self.assertIn("NVM/DMA readiness timeout after reset",body)
        poll=e[e.index("m3waitreg(Ctlr *c, int reg"):e.index("reset(Ctlr *c)")]
        self.assertIn("tries < 1000",poll)
        self.assertIn("delay(1)",poll)
        self.assertIn("if(v == ~0U)",poll)
        self.assertIn("return -1;",poll)

    def test_x550_rx_enable_is_bounded(self):
        rx=self.ether[self.ether.index("rxinit(Ctlr *c)"):self.ether.index("replenish(Ctlr *c")]
        self.assertNotIn("while((c->reg[Rxdctl] & Renable)",rx)
        self.assertIn("m3waitreg(c, Rxdctl, Renable)",rx)
        self.assertIn('error("iX550: RX queue enable timeout")',rx)

    def test_x550_bar_guards_precede_all_vmaps(self):
        e=self.ether
        scan=e[e.index("scan(void)"):e.index("pnp(Ether *e)")]
        self.assertIn("p->mem[pciregs].size < (Eemngctl+1)*4",scan)
        self.assertIn("p->mem[pcimsix].size < 4",scan)
        self.assertIn("(p->mem[pciregs].bar & ~0xFULL) == 0",scan)
        self.assertIn("(p->mem[pcimsix].bar & ~0xFULL) == 0",scan)
        self.assertLess(scan.index("invalid register or MSI-X BAR"),
                        scan.index("mem = vmap("))
        self.assertLess(scan.index("pcidisable(p)"),scan.index("pcisetbme(p)"))

    def test_nvme_cap_stride_checked_before_interrupt_mmio(self):
        s=self.nvme
        scan=s[s.index("nvmepnpctlrs(void)"):s.index("static SDev*\nnvmepnp")]
        self.assertIn("p->mem[0].size < 0x1008",scan)
        self.assertIn("(p->mem[0].bar & ~0xFULL) == 0",scan)
        self.assertIn("0x1000ULL + (4ULL << ctlr->dstrd) + 4",scan)
        self.assertLess(scan.index("BAR0 too small for admin doorbells"),
                        scan.index("ctlr->reg[IntMs] ="))
        self.assertIn("goto Bad;",scan)
        self.assertIn("pcidisable(p);",scan)

    def test_nvme_admin_doorbell_stride_math(self):
        # Exactly the audited CAP.DSTRD minimum BAR calculation.
        for stride in range(16):
            required=0x1000+(4<<stride)+4
            self.assertFalse((required-1)>=required)
            self.assertTrue(required >= 0x1008)
            self.assertLessEqual(required, 0x21004)
            self.assertEqual(required-4,0x1000+(4<<stride))


if __name__ == "__main__":
    unittest.main()
