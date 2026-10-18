# SPDX-License-Identifier: AGPL-3.0-only
"""Static regression guards for D2 storage safety patches (not hardware tests)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class D2StorageSafety(unittest.TestCase):
    def test_nvme_zero_progress_is_rejected(self):
        s = (ROOT / "sys/src/9/port/sdnvme.c").read_text()
        self.assertRegex(s, r"if\(s == 0\)\s*error\(")
        self.assertRegex(s, r"m = \(2\*ctlr->mps[^;]+;\s*if\(m == 0\)\s*error\(")

    def test_virtio_completion_chains_validated(self):
        for path in ("sys/src/9/port/sdvirtio10.c", "sys/src/9/pc/sdvirtio.c"):
            with self.subTest(path=path):
                s = (ROOT / path).read_text()
                f = s[s.index("vqinterrupt(Vqueue *q)"):s.index("viointerrupt(Ureg *", s.index("vqinterrupt(Vqueue *q)"))]
                self.assertIn("if((uint)next >= (uint)q->size)", f)
                self.assertIn("if(n == q->size || (uint)next >= (uint)q->size)", f)
                self.assertLess(f.index("if(n == q->size"), f.index("q->rock[id]"))
                self.assertLess(f.index("if(n == q->size"), f.index("q->desc[free].next"))


if __name__ == "__main__":
    unittest.main()
