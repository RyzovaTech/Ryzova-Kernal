# SPDX-License-Identifier: AGPL-3.0-only
"""M5.2 / M5.3 kernel lifecycle + honest evidence qualification tests."""
import copy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from m5_server_gates import report, arm64_evidence
from m5_platform_audit import audit

class M5ServerGates(unittest.TestCase):
    def setUp(self):
        self.p=audit(ROOT)

    def test_irq_registration_has_validity_capacity_and_cleanup_guards(self):
        s=(ROOT/"sys/src/9/arm64/pciqemu.c").read_text()
        self.assertIn('if(f == nil)',s)
        self.assertIn('PCI handler table full',s)
        self.assertIn('if(v->f == f && v->p == p && v->a == a)',s)
        self.assertIn('freeidx = -1;',s)
        self.assertIn('v->f = f;',s)
        self.assertIn('v->f = nil;',s)
        self.assertIn('v->a = nil;',s)
        self.assertIn('v->p = nil;',s)
        self.assertLess(s.index('v->a = a;'),s.index('v->f = f;'))

    def test_build_report_never_implies_arm64_operational(self):
        for cross in ({},{'cross_compiler_7c':'pass','arm64_kernel_link':'blocked'},
                      {'cross_compiler_7c':'pass','arm64_kernel_link':'pass'}):
            r=report(self.p,cross)
            self.assertFalse(r["m5_full_complete"])
            self.assertFalse(r["m5_1_arm64_boot_certified"])
            self.assertFalse(r["m5_2_arm64_virtio_network_certified"])
            self.assertFalse(r["m5_2_arm64_virtio_storage_certified"])
            self.assertFalse(r["m5_3_arm64_smp_irq_dma_certified"])
            self.assertEqual(r["physical_hardware_models_newly_certified"],0)
            self.assertTrue(r["ready_for_m6_planning"])
            self.assertFalse(r["ready_for_m6_hardware_release"])

    def test_serial_only_is_not_approved_as_evidence(self):
        serial=(b"Plan 9\r\ncpu0: 1000MHz QEMU\r\n"
                b"M5_ARM64_NET_IO_OK\r\nM5_ARM64_DISK_SHA_OK\r\n"
                b"M5_ARM64_SMP_IRQ_OK\r\n")
        observations=arm64_evidence(serial)
        self.assertTrue(all(observations.values()))
        r=report(self.p,{"cross_compiler_7c":"pass",
                         "arm64_kernel_link":"pass"},serial)
        self.assertFalse(r["m5_full_complete"])
        self.assertFalse(r["m5_1_arm64_boot_certified"])
        self.assertEqual(r["native_arm64_serial_observations_unattested"],observations)

    def test_echos_not_full_lines(self):
        serial=b"term% echo M5_ARM64_NET_IO_OK; echo M5_ARM64_DISK_SHA_OK\r\n"
        o=arm64_evidence(serial)
        self.assertFalse(o["virtio_net_datapath"])
        self.assertFalse(o["virtio_storage_integrity"])
        with self.assertRaises(ValueError):
            report({"arm64_native_boot_confirmed":True})

if __name__=="__main__":
    unittest.main()
