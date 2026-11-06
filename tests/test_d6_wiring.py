# SPDX-License-Identifier: AGPL-3.0-only
"""Priority 6 integration guard: discovery is opt-in, GPU wire code is unlinked."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class D6IntegrationTests(unittest.TestCase):
    def test_bluetooth_manual_probe(self):
        s = (ROOT / "sys/src/cmd/nusb/bt/bt.c").read_text()
        self.assertIn("CSP(Btclass, Btsubclass, Btprotocol)", s)
        self.assertIn("ep->type == Eintr && ep->dir == Ein", s)
        self.assertIn("bthcieventvalid(buf, n)", s)
        self.assertIn("if(dorestart)", s)
        self.assertLess(s.index("if(dorestart)"), s.index("usbcmd(dev, Rh2d|Rclass|Rdev"))
        self.assertIn("bt\\\n", (ROOT / "sys/src/cmd/nusb/mkfile").read_text())

    def test_gpu_helpers_not_falsely_enabled_as_kernel_driver(self):
        config = (ROOT / "sys/src/9/pc64/pc64").read_text()
        self.assertNotIn("virtgpuwire", config)
        self.assertTrue((ROOT / "sys/src/9/port/virtgpuwire.c").is_file())


if __name__ == "__main__":
    unittest.main()
