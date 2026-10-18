# SPDX-License-Identifier: AGPL-3.0-only
"""M2 isolated PCI guest parser only accepts real QEMU diagnostic output."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from m2_qemu_probe import validate_serial


class M2QemuEvidence(unittest.TestCase):
    def setUp(self):
        self.good = (
            b"term% grep 'candidate=m2-' '#P/drivercandidates'; echo RYZOVA_M2_PCI_OK\r\n"
            b"PCI.0.6.0 1022:2000 class 02:00:00 rev 10 candidate=m2-amd-pcnet-2000-candidate verified=no\r\n"
            b"PCI.0.7.0 10ec:8139 class 02:00:00 rev 20 candidate=m2-realtek-rtl8139-candidate verified=no\r\n"
            b"RYZOVA_M2_PCI_OK\r\n"
        )

    def test_two_pci_candidates_and_success_marker(self):
        self.assertTrue(validate_serial(self.good))

    def test_echo_only_is_not_discovery(self):
        line=b"term% echo 'candidate=m2-amd-pcnet-2000-candidate candidate=m2-realtek-rtl8139-candidate'\r\n"
        self.assertFalse(validate_serial(line+b"RYZOVA_M2_PCI_OK\r\n"))

    def test_missing_or_false_claim_rejected(self):
        self.assertFalse(validate_serial(self.good.replace(b"RTL8139",b"RTL8138")))
        self.assertFalse(validate_serial(self.good.replace(b"m2-realtek-rtl8139-candidate",b"m2-other-candidate")))
        self.assertFalse(validate_serial(self.good.replace(b"verified=no",b"verified=yes")))
        self.assertFalse(validate_serial(self.good.replace(b"RYZOVA_M2_PCI_OK\r\n",b"")))
        self.assertFalse(validate_serial(b""))

    def test_wrong_index_format_rejected(self):
        self.assertFalse(validate_serial(self.good.replace(b"PCI.0.7.0",b"UHD.0.7.0")))


if __name__ == "__main__":
    unittest.main()
