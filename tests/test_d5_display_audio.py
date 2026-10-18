# SPDX-License-Identifier: AGPL-3.0-only
"""Intel display and HDA static safety regression, not physical validation."""
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class DisplayAudioGuards(unittest.TestCase):
    def test_intel_graphics_blank_mmio_guard(self):
        s=(ROOT / "sys/src/9/pc/vgaigfx.c").read_text()
        f=s[s.index("igfxblank(VGAscr *scr"):s.index("igfxdrawinit(VGAscr *scr")]
        self.assertLess(f.index("scr->pci == nil || scr->mmio == nil"),f.index("switch(scr->pci->did)"))
        self.assertLess(f.index("(uvlong)off + sizeof(u32int)"),f.index("scr->mmio[off/4]"))
    def test_intel_cursor_register_bounds(self):
        s=(ROOT / "sys/src/9/pc/vgaigfx.c").read_text()
        f=s[s.index("igfxcurregs(VGAscr* scr"):s.index("igfxcurmove(VGAscr* scr")]
        self.assertIn("pipe < 0 || pipe >= NPIPE",f)
        self.assertLess(f.index("(uvlong)(0x70008 | o)"),f.index("scr->mmio[(0x70008 | o)/4]"))
        self.assertLess(f.index("(uvlong)(0x70080 + o)"),f.index("return (u32int*)((uchar*)scr->mmio"))
    def test_audio_hda_bar0(self):
        s=(ROOT / "sys/src/9/pc/audiohda.c").read_text()
        f=s[s.index("hdareset1(Audio *adev"):s.index("hdareset(Audio *adev")]
        self.assertIn("p->mem[0].size == 0",f)
        self.assertIn("(p->mem[0].bar & ~0xFULL) == 0",f)
        self.assertLess(f.index("p->mem[0].size == 0"),f.index("vmap(ctlr->port"))

if __name__ == "__main__":
    unittest.main()
