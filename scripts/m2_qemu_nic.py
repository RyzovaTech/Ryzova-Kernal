#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M2 regression helper: identify original VirtIO NIC after emulated PCI additions."""
import re


def legacy_safe_network_command(command, serial, m2_enabled):
    """Keep M2 emulated chipset PCI discovery from changing baseline network NIC."""
    if not m2_enabled or "/net/ether0" not in command:
        return command
    if not isinstance(serial, (bytes, bytearray)):
        raise ValueError("serial evidence must be bytes")
    matches = re.findall(rb"(?:^|\r?\n)#l(\d+): virtio:", serial)
    if not matches:
        raise ValueError("virtio network interface not found in fresh boot serial")
    idx = int(matches[-1])
    if idx > 31:
        raise ValueError("unexpected NIC index")
    return command.replace("/net/ether0", "/net/ether" + str(idx))
