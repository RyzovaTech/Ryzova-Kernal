# SPDX-License-Identifier: AGPL-3.0-only
"""Static regression: i225 failed MMIO mapping must not unmap a nil address.

The native kernel CI checks that the real C kernel still compiles and boots.
This test only protects the specific source-level error-path invariant.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "sys/src/9/pc/etheri225.c"


class I225MmioFailureTests(unittest.TestCase):
    def test_mmio_failure_frees_controller_without_unmapping_nil(self):
        source = FILE.read_text(encoding="utf-8")
        match = re.search(
            r"c->portmmio\s*=\s*vmap\s*\([^;]+;\s*"
            r"if\s*\(\s*c->portmmio\s*==\s*nil\s*\)\s*\{([^}]*)\}",
            source, flags=re.S
        )
        self.assertIsNotNone(match, "i225 MMIO mapping failure path was not found")
        cleanup = match.group(1)
        self.assertRegex(cleanup, r"\bfree\s*\(\s*c\s*\)")
        self.assertRegex(cleanup, r"\bcontinue\s*;")
        self.assertNotRegex(cleanup, r"\bvunmap\s*\(")

    def test_valid_mapping_still_exposes_pci_probe_ids(self):
        text = FILE.read_text(encoding="utf-8")
        self.assertIn("case 0x15f3:", text)  # Intel I225-V source-level probe
        self.assertIn("case 0x125c:", text)  # Intel I226-V source-level probe


if __name__ == "__main__":
    unittest.main()
