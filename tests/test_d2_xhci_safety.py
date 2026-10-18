# SPDX-License-Identifier: AGPL-3.0-only
"""Source-level USB xHCI safety guards, not a physical device test."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class XhciGuards(unittest.TestCase):
    def test_port_callbacks_reject_invalid_indices(self):
        s = (ROOT / "sys/src/9/port/usbxhci.c").read_text()
        for name in ("portstatus", "portenable", "portreset", "bhportreset", "portpower"):
            with self.subTest(name=name):
                m = re.search(r"static (?:void|int)\s+" + name + r"\(Hci \*hp, int port(?:, int on)?\)\s*\{(.*?)\n\}", s, re.S)
                self.assertIsNotNone(m, name)
                self.assertIn("port < 1 || port > hp->nports", m.group(1))

    def test_controller_limit_releases_mapping(self):
        s = (ROOT / "sys/src/9/port/usbxhcipci.c").read_text()
        m = re.search(r"if\(i >= nelem\(ctlrs\)\)\s*\{(.*?)\}", s, re.S)
        self.assertIsNotNone(m)
        self.assertIn("vunmap(mmio, iosize)", m.group(1))
        self.assertIn("free(ctlr)", m.group(1))

if __name__ == "__main__":
    unittest.main()
