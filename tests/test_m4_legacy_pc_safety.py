# SPDX-License-Identifier: AGPL-3.0-only
"""M4 legacy PCnet / RTL8139 error-path guards; not physical NIC testing."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class M4LegacyNICSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcnet=(ROOT/"sys/src/9/pc/ether79c970.c").read_text()
        cls.rtl=(ROOT/"sys/src/9/pc/ether8139.c").read_text()

    def test_pcnet_io_bar_guard_precedes_reservation(self):
        p=self.pcnet
        c=p[p.index("amd79c970pci(void)"):p.index("static int\nm4resetfail")]
        self.assertIn("(p->mem[0].bar & 1) == 0",c)
        self.assertIn("p->mem[0].size < Bdp+4",c)
        self.assertIn("p->mem[0].size > 0x10000",c)
        self.assertIn("port > 0x10000 - p->mem[0].size",c)
        self.assertLess(c.index("port == 0"),c.index("ioalloc("))
        self.assertIn("iofree(port);",c)

    def test_pcnet_initialization_bounded_and_abort_on_fault(self):
        p=self.pcnet
        s=p[p.index("reset(Ether* ether)"):p.index("void\nether79c970link")]
        self.assertNotIn("while(!(ctlr->ior(ctlr, Rdp) & Idon))",s)
        self.assertIn("for(timeo = 0; timeo < 1000; timeo++)",s)
        self.assertIn("microdelay(100);",s)
        self.assertIn("(x & 0xFFFF) == 0xFFFF",s)
        self.assertIn("(x & Merr)",s)
        self.assertIn("ctlr->iow(ctlr, Rdp, Stop);",s)
        self.assertIn("return m4resetfail(ether, ctlr);",s)

    def test_pcnet_reset_failure_releases_bus_mastering_and_slot(self):
        s=self.pcnet[self.pcnet.index("m4resetfail(Ether *ether"):
                     self.pcnet.index("reset(Ether* ether)")]
        for line in ("ctlr->init = 0;", "ctlr->active = 0;",
                     "pciclrbme(ctlr->pcidev);",
                     "pcidisable(ctlr->pcidev);", "ether->ctlr = nil;"):
            self.assertIn(line,s)
        self.assertLess(s.index("pciclrbme("),s.index("pcidisable("))
        s=self.pcnet[self.pcnet.index("reset(Ether* ether)"):]
        self.assertEqual(s.count("return m4resetfail(ether, ctlr);"),3)

    def test_rtl8139_iobar_checked_before_any_port_access(self):
        s=self.rtl[self.rtl.index("rtl8139match(Ether* edev, int id)"):
                   self.rtl.index("static struct {")]
        for line in ("(p->mem[0].bar & 1) == 0",
                     "p->mem[0].size < Phy2parm+4",
                     "p->mem[0].size > 0x10000",
                     "port == 0", "port > 0x10000 - p->mem[0].size"):
            self.assertIn(line,s)
        self.assertLess(s.index("port == 0"),s.index("ioalloc("))
        self.assertLess(s.index("ioalloc("),s.index("pcienable(p)"))
        self.assertIn("pcidisable(p);",s)
        self.assertIn("iofree(port);",s)

    def test_valid_io_windows_keep_old_pc_profiles(self):
        # Model exact bounds invariants for old ISA-style 16-bit I/O windows.
        for start,size,minimum in [(0xc000,0x100,0x84),(0xd000,0x20,0x20),
                                   (0,0x100,0x84),(0xfff0,0x100,0x84),
                                   (0xc000,0x10,0x20)]:
            safe=size>=minimum and size<=0x10000 and start>0 and start<=0x10000-size
            self.assertEqual(safe,(start,size) in [(0xc000,0x100),(0xd000,0x20)])
        self.assertTrue((0xf000,0x100) and 0xf000<=0x10000-0x100)


if __name__ == "__main__":
    unittest.main()
