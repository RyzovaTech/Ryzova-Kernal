# SPDX-License-Identifier: AGPL-3.0-only
"""M2 detects displaced VirtIO interface without hard-coded PCI index."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from m2_qemu_nic import legacy_safe_network_command


class M2NetworkBaseline(unittest.TestCase):
    def test_no_emulated_chipset_preserves_old_guest_network(self):
        command="ip/ipconfig -d ether /net/ether0; webfs"
        self.assertEqual(legacy_safe_network_command(command, b"", False), command)

    def test_pcnet_realtek_and_virtio_network_index(self):
        serial=(b"#l0: pcnet: 100Mbps\r\n"
                b"#l1: rtl8139: 100Mbps\r\n"
                b"#l2: virtio: 1000Mbps\r\n")
        text=legacy_safe_network_command("ip/ipconfig -d ether /net/ether0",serial, True)
        self.assertEqual(text,"ip/ipconfig -d ether /net/ether2")

    def test_hard_fail_when_virtio_missing_or_index_unbounded(self):
        with self.assertRaises(ValueError):
            legacy_safe_network_command("ip/ipconfig -d ether /net/ether0",b"#l1: rtl8139:\n",True)
        with self.assertRaises(ValueError):
            legacy_safe_network_command("ip/ipconfig -d ether /net/ether0",b"#l999: virtio:\n",True)

    def test_does_not_rewrite_unrelated_guest_commands(self):
        text="hget http://10.0.2.2:8000/network-probe.txt"
        self.assertEqual(legacy_safe_network_command(text,b"",True),text)


if __name__ == "__main__":
    unittest.main()
