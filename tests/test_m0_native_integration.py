# SPDX-License-Identifier: AGPL-3.0-only
"""M0 native Ryzova pc64 read-only wiring and reviewed PCI rules."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import m0_native_rules
import m0_device_registry as m0


class M0NativeIntegration(unittest.TestCase):
    def test_generated_rules_are_exactly_in_sync_with_source_registry(self):
        generated = m0_native_rules.generate(ROOT)
        self.assertEqual(generated, (ROOT / m0_native_rules.OUTPUT).read_text())
        reg = m0.read_json(ROOT / m0_native_rules.REGISTRY)
        self.assertEqual(generated.count("{RzbusPci, "), sum(r["bus"] == "pci" for r in reg["rules"]))
        self.assertNotIn("{RzbusUsb,", generated)

    def test_kernel_configuration_compiles_native_matcher_and_adapter(self):
        config = (ROOT / "sys/src/9/pc64/pc64").read_text()
        main = (ROOT / "sys/src/9/pc64/main.c").read_text()
        fns = (ROOT / "sys/src/9/pc64/fns.h").read_text()
        self.assertIn("\tryzovadrvmatch\n", config)
        self.assertIn("\tryzovadrvprobe\n", config)
        self.assertIn("void\tryzovadrvprobeinit(void);", fns)
        self.assertIn("ryzovadrvprobeinit();", main)
        self.assertLess(main.index("pcicfginit();"), main.index("ryzovadrvprobeinit();"))
        self.assertLess(main.index("ryzovadrvprobeinit();"), main.index("bootscreeninit();"))

    def test_read_only_arch_file_does_not_bind_devices(self):
        source = (ROOT / "sys/src/9/port/ryzovadrvprobe.c").read_text()
        self.assertIn('addarchfile("drivercandidates", 0444, rzpciread, nil)', source)
        self.assertIn("pcimatch(p, 0, 0)", source)
        self.assertIn("rzdrvmatch(&key, rzpcirules", source)
        self.assertIn("key.revision = p->rid;", source)
        self.assertIn("key.classcode = p->ccrb;", source)
        self.assertIn("Rzscanlimit = 512", source)
        self.assertIn("Rzshowlimit = 24", source)
        self.assertIn("verified=no", source)
        self.assertIn("auto-bind=no", source)
        self.assertEqual(source.count("pcimatch("), 1)
        for forbidden in ("pcienable(", "pcisetbme(", "pcicfgw", "vmap(",
                          "intrenable(", "pcimsienable(", "dmaalloc("):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("ryzovadrvprobeinit();", source[:source.index("void\nryzovadrvprobeinit")])

    def test_m0_rejects_fabricated_pci_binding_policy(self):
        data = m0.read_json(ROOT / m0_native_rules.REGISTRY)
        changed = copy.deepcopy(data)
        changed["binding_enabled"] = True
        with self.assertRaises(m0.RegistryError):
            m0_native_rules.CandidateIndex(
                changed, m0.read_json(ROOT / m0_native_rules.FIRMWARE), ROOT)


if __name__ == "__main__":
    unittest.main()
