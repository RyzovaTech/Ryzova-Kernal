#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Drive a disposable 9front QEMU serial boot to probe access to its native rc shell.

This is an experimental prerequisite for building exact Ryzova source IN the 9front VM.
It does NOT compile or boot Ryzova kernel sources.
"""
from __future__ import annotations
import os
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

ART = Path("artifacts/guest-console").resolve()
ART.mkdir(parents=True, exist_ok=True)
SER = ART / "serial.sock"
MON = ART / "monitor.sock"
img = Path(sys.argv[1]).resolve()
qemu_cmd = [
    "qemu-system-x86_64",
    "-machine", "pc,accel=tcg", "-cpu", "qemu64", "-m", "1024", "-smp", "2",
    "-device", "virtio-scsi-pci,id=scsi",
    "-drive", f"if=none,id=vd0,file={img},format=qcow2",
    "-device", "scsi-hd,drive=vd0",
    "-device", "virtio-net-pci,netdev=n0", "-netdev", "user,id=n0",
    "-vga", "std", "-display", "none",
    "-chardev", f"socket,id=uart,path={SER},server=on,wait=off",
    "-serial", "chardev:uart",
    "-monitor", f"unix:{MON},server=on,wait=off", "-no-reboot", "-no-shutdown",
]
state = dict(bootargs=False, user=False, vgasize=False, probe=False)
probe_at = 0.0
log = bytearray()
print("Starting serial-driven official 9front guest; Ryzova source has NOT been built.",flush=True)
with (ART/"qemu-host.log").open("wb") as host:
    proc=subprocess.Popen(qemu_cmd,stdout=host,stderr=subprocess.STDOUT)
    try:
        guest=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        for _ in range(200):
            try:
                guest.connect(str(SER))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(.15)
        else:
            raise RuntimeError("Guest serial socket not ready")
        guest.setblocking(False)
        deadline=time.monotonic()+165
        stage_msg=[]
        while time.monotonic()<deadline:
            if proc.poll() is not None:
                stage_msg.append("QEMU unexpectedly exited")
                break
            ready,_,_=select.select([guest],[],[],.4)
            if ready:
                try: new=guest.recv(65536)
                except BlockingIOError: new=b""
                if new:
                    log.extend(new)
                    recent=bytes(log[-12000:]).decode("utf-8",errors="replace").lower()
                    if "bootargs is " in recent and not state["bootargs"]:
                        guest.sendall(b"\r")
                        state["bootargs"]=True
                        probe_at=time.monotonic()
                        stage_msg.append("Responded to bootargs prompt")
                    if ("user[glenda]" in recent or "user:" in recent) and not state["user"] and state["bootargs"]:
                        guest.sendall(b"glenda\r")
                        state["user"]=True
                        stage_msg.append("Responded to user prompt")
                    if "vgasize" in recent and not state["vgasize"] and state["bootargs"]:
                        guest.sendall(b"text\r")
                        state["vgasize"]=True
                        stage_msg.append("Selected text display")
            if state["bootargs"] and not state["probe"] and time.monotonic()-probe_at>55:
                # Verify guest shell by a command whose *output* differs from its input.
                guest.sendall(b"echo PROBE_MARKER | tr A-Z a-z\r")
                state["probe"]=True
                stage_msg.append("Sent rc-shell probe (may fail if no shell)")
            if state["probe"] and b"probe_marker" in bytes(log):
                stage_msg.append("Guest shell successfully executed a command")
                break
        guest.close()
    finally:
        try:
            ctl=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            ctl.settimeout(3)
            ctl.connect(str(MON))
            ctl.recv(4096)
            ctl.sendall(f"screendump {ART/'screen.ppm'}\n".encode())
            ctl.close()
        except Exception as e:
            print("Screenshot unavailable:",e)
        (ART/"serial.log").write_bytes(log)
        (ART/"summary.txt").write_text("\n".join(stage_msg+[
            f"Bootargs prompt answered: {state['bootargs']}",
            f"Guest shell probe executed: {b'probe_marker' in bytes(log).lower()}",
            "This probe does not compile or boot the Ryzova source."
        ])+"\n")
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()
        print("\n".join(stage_msg))
        print("Serial tail:",bytes(log[-4500:]).decode("utf-8",errors="replace"))
if b"probe_marker" not in bytes(log).lower():
    print("FAIL: native rc shell could not be confirmed; examine artifacts.",file=sys.stderr)
    sys.exit(1)
print("PASS: native 9front rc shell command execution confirmed. Source build remains pending.")
