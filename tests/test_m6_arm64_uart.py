# SPDX-License-Identifier: AGPL-3.0-only
"""PL011 QEMU console RX interrupt contract; never a runtime boot certificate."""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UART = ROOT / "sys/src/9/arm64/uartqemu.c"
IRQ = ROOT / "sys/src/9/arm64/io.h"


class M6Arm64QemuUart(unittest.TestCase):
    def test_pl011_receive_fifo_timeout_is_unmasked(self):
        s = UART.read_text()
        self.assertRegex(s, r"RTIM\s*=\s*1<<6")
        self.assertRegex(s, r"RXIM\s*=\s*1<<4")
        self.assertRegex(s, r"FEN\s*=\s*1<<4")
        self.assertIn("reg[IMSC] = TXIM|RXIM|RTIM;", s)

    def test_rx_interrupt_drains_uart_fifo_and_acks_timeout(self):
        s = UART.read_text()
        irq=s[s.index("static void\ninterrupt("):s.index("static void\ndisable(")]
        self.assertIn("while((reg[FR] & RXFE) == 0)", irq)
        self.assertIn("uartrecv(uart, reg[DR] & 0xFF)", irq)
        self.assertIn("reg[ICR] = 1<<5 | 1<<6", irq)

    def test_qemu_uart_is_attached_to_GIC_SPI_33(self):
        s = IRQ.read_text()
        self.assertRegex(s,r"SPI\s*=\s*32")
        self.assertRegex(s,r"IRQuart\s*=\s*SPI\+1")
        uart = UART.read_text()
        self.assertIn("intrenable(IRQuart, interrupt, uart, BUSUNKNOWN, uart->name)", uart)

    def test_console_input_does_not_replace_evidence_gate(self):
        probe = (ROOT/"scripts/m6_arm64_virtio_probe.py").read_text()
        acceptance = (ROOT/"scripts/m6_arm64_virtio_acceptance.py").read_text()
        self.assertIn('proc.stdin.write(b"!rc\\r")', probe)
        self.assertIn('io.get("guest_shell_reached") is True', acceptance)
        self.assertIn('io.get("http_guest_request_observed") is True', acceptance)
        self.assertIn('io.get("host_ephemeral_disk_write_verified") is True', acceptance)


if __name__ == "__main__":
    unittest.main()
