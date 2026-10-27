#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Isolated third QEMU guest: source-built Ryzova PCI chipset discovery only.

Keeps network-sensitive legacy baseline boot separate from synthetic PCI NICs.
No ethernet data-path or physical chipset certification is performed.
"""
from pathlib import Path
import re
import select
import socket
import subprocess
import time
from qemu_control import control_socket, control_address

CANDIDATES = ((b"1022:2000", b"m2-amd-pcnet-2000-candidate"),
              (b"10ec:8139", b"m2-realtek-rtl8139-candidate"))


def validate_serial(data):
    """Require output lines, not copied command echo or fabricated source IDs."""
    if not re.search(rb"(?:^|\r?\n)RYZOVA_M2_PCI_OK(?:\r?\n)", data):
        return False
    return all(
        re.search(rb"(?:^|\r?\n)PCI\.[0-9]+\.[0-9]+\.[0-9]+ " +
                  re.escape(pci_id) + rb" [^\r\n]{1,135}candidate=" +
                  re.escape(name) + rb" verified=no(?:\r?\n)", data)
        for pci_id, name in CANDIDATES
    )


def legacy_memory_cmd(base_cmd, mib):
    """Override QEMU guest memory without duplicating -m on its command line."""
    if type(mib) is not int or not 128 <= mib <= 4096:
        raise ValueError("unsafe legacy guest memory size")
    if base_cmd.count("-m") != 1:
        raise ValueError("QEMU memory configuration is ambiguous")
    cmd = list(base_cmd)
    cmd[cmd.index("-m")+1] = str(mib)
    return cmd


def run_probe(base_cmd, serial_path, monitor_path, output_dir, memory_mib=None):
    if memory_mib is not None:
        base_cmd = legacy_memory_cmd(base_cmd, memory_mib)
    serial_path = Path(serial_path)
    monitor_path = Path(monitor_path)
    output_dir = Path(output_dir)
    serial_path.unlink(missing_ok=True)
    monitor_path.unlink(missing_ok=True)
    extra = [
        "-netdev", "user,id=m2pcnet", "-device", "pcnet,netdev=m2pcnet",
        "-netdev", "user,id=m2rtl", "-device", "rtl8139,netdev=m2rtl",
    ]
    report = bytearray()
    bootargs = login = sent = False
    with (output_dir / "m2-qemu-host.log").open("wb") as host:
        guest = subprocess.Popen(base_cmd + extra, stdout=host, stderr=subprocess.STDOUT)
        client = control_socket(serial_path)
        try:
            for _ in range(300):
                try:
                    client.connect(control_address(serial_path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if guest.poll() is not None:
                        raise RuntimeError("isolated M2 QEMU guest exited before serial connection")
                    time.sleep(.1)
            else:
                raise RuntimeError("isolated M2 serial socket never became available")
            client.setblocking(False)
            deadline = time.monotonic() + 85
            while time.monotonic() < deadline:
                if guest.poll() is not None:
                    break
                ready, _, _ = select.select([client], [], [], .2)
                if ready:
                    try:
                        chunk = client.recv(65536)
                    except BlockingIOError:
                        chunk = b""
                    if chunk:
                        report.extend(chunk)
                tail = bytes(report[-16000:])
                if b"bootargs is " in tail and not bootargs:
                    client.sendall(b"\r")
                    bootargs = True
                if bootargs and (b"user[glenda]:" in tail or b"user:" in tail) and not login:
                    client.sendall(b"glenda\r")
                    login = True
                if login and b"term%" in tail and not sent:
                    client.sendall(b"grep 'candidate=m2-' '#P/drivercandidates'; echo RYZOVA_M2_PCI_OK\r")
                    sent = True
                if sent and validate_serial(bytes(report)):
                    break
        finally:
            (output_dir / "m2-chipset-probe-serial.log").write_bytes(report)
            guest.terminate()
            try:
                guest.wait(timeout=8)
            except subprocess.TimeoutExpired:
                guest.kill()
            client.close()
    return validate_serial(bytes(report))
