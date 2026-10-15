#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build imported Ryzova source inside a disposable 9front AMD64 QEMU guest.

Strict gate: an official prebuilt guest boot and source parity are NOT the same as
a successful fresh build. This workflow stops before claiming V3 until V2 works.
"""
from __future__ import annotations

import http.server
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "phase3"
OUT.mkdir(parents=True, exist_ok=True)
SER = OUT / "serial.sock"
MON = OUT / "monitor.sock"
ARCHIVE = OUT / "kernel-source.tar.gz"
GUEST_IMAGE = Path(sys.argv[1]).resolve()
SOURCE_SHA = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()

subprocess.run(["tar", "--format=ustar", "-czf", str(ARCHIVE), "-C", str(ROOT), "sys/src/9", "sys/include", "amd64/include"], check=True)
archive_hash = subprocess.check_output(["sha256sum", str(ARCHIVE)], text=True).split()[0]
(OUT / "source-provenance.txt").write_text(
    f"Ryzova source commit: {SOURCE_SHA}\nKernel subtree archive sha256: {archive_hash}\n"
    "Archive includes kernel source, sys/include, amd64/include from exactly the checked-out commit.\n"
)
print("SOURCE_SHA", SOURCE_SHA, "ARCHIVE_SHA256", archive_hash, flush=True)

class LocalHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(OUT), **kwargs)
    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args, flush=True)

server = http.server.ThreadingHTTPServer(("0.0.0.0", 8000), LocalHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()

cmd = [
    "qemu-system-x86_64",
    "-machine", "pc,accel=tcg", "-cpu", "qemu64", "-m", "2048", "-smp", "2",
    "-device", "virtio-scsi-pci,id=scsi",
    "-drive", f"if=none,id=vd0,file={GUEST_IMAGE},format=qcow2",
    "-device", "scsi-hd,drive=vd0",
    "-device", "virtio-net-pci,netdev=n0", "-netdev", "user,id=n0",
    "-vga", "std", "-display", "none",
    "-chardev", f"socket,id=uart,path={SER},server=on,wait=off",
    "-serial", "chardev:uart",
    "-monitor", f"unix:{MON},server=on,wait=off",
    "-no-reboot", "-no-shutdown",
]
# The 9front rc shell is used for ALL target compilation, not Linux gcc/make.
stages = [
    ("guest-network", "ip/ipconfig -d ether /net/ether0; webfs; echo PHASE3_END_0"),
    ("fetch-repository-source",
     "hget http://10.0.2.2:8000/kernel-source.tar.gz > /tmp/kernel-source.tar.gz; "
     "ls -l /tmp/kernel-source.tar.gz; echo PHASE3_END_1"),
    ("install-exact-kernel-source",
     "cd /; tar xzf /tmp/kernel-source.tar.gz; "
     "cd /sys/src/9/pc64; ls -l main.c mkfile; echo PHASE3_END_2"),
    ("native-amd64-mk",
     "cd /sys/src/9/pc64; mk > /tmp/ryzova-native-build.log >[2=1]; "
     "echo PHASE3_MK_STATUS_$status; tail -n 90 /tmp/ryzova-native-build.log; ls -l 9pc64; "
     "echo PHASE3_END_3"),
    ("inspect-boot-disk",
     "9fs 9fat; ls -l /n/9fat; cat /n/9fat/plan9.ini; echo PHASE3_END_4"),
    ("install-fresh-bootfile",
     "cd /sys/src/9/pc64; cp 9pc64 /n/9fat/9pc64; "
     "cmp 9pc64 /n/9fat/9pc64; echo PHASE3_COPY_STATUS_$status; "
     "ls -l /n/9fat/9pc64; echo PHASE3_END_5"),
]
raw=bytearray()
session = dict(bootargs=False, user=False, shell=False, stage=0, sent=False, final=False)
marks = {}
with (OUT/"host.log").open("wb") as host:
    proc=subprocess.Popen(cmd,stdout=host,stderr=subprocess.STDOUT)
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        for _ in range(300):
            try:
                client.connect(str(SER))
                break
            except (FileNotFoundError,ConnectionRefusedError):
                time.sleep(.1)
        else: raise RuntimeError("serial socket unavailable")
        client.setblocking(False)
        started=time.monotonic()
        stage_start=started
        while time.monotonic()-started<750:
            if proc.poll() is not None:
                print("QEMU exited unexpectedly",flush=True)
                break
            readable,_,_=select.select([client],[],[],.4)
            if readable:
                try: data=client.recv(65536)
                except BlockingIOError: data=b""
                if data:
                    raw.extend(data)
                    tail=bytes(raw[-18000:])
                    if b"bootargs is " in tail and not session["bootargs"]:
                        client.sendall(b"\r")
                        session["bootargs"]=True
                        print("Answered bootargs",flush=True)
                    if (b"user[glenda]:" in tail or b"user:" in tail) and not session["user"] and session["bootargs"]:
                        client.sendall(b"glenda\r")
                        session["user"]=True
                        print("Answered user prompt",flush=True)
                    if b"term%" in tail and session["user"]:
                        session["shell"]=True
            if session["shell"] and session["stage"]<len(stages):
                ix=session["stage"]
                label,command=stages[ix]
                if not session["sent"]:
                    client.sendall((command+"\r").encode())
                    session["sent"]=True
                    stage_start=time.monotonic()
                    print("SENT STAGE",ix,label,flush=True)
                # Terminal echo can contain marker as an argument. Look for the standalone
                # line, which is printed only after the shell executed it.
                expected=rb"(?:\r?\n)PHASE3_END_"+str(ix).encode()+rb"(?:\r?\n)"
                if re.search(expected,bytes(raw)[-120000:]):
                    marks[label]=True
                    session["stage"]+=1
                    session["sent"]=False
                    print("PASSED STAGE",ix,label,flush=True)
                    if ix==5:
                        session["final"]=True
                        break
                if time.monotonic()-stage_start>380:
                    print("STAGE TIMEOUT",ix,label,flush=True)
                    break
        print("Stages:",marks,flush=True)
    finally:
        (OUT/"serial.log").write_bytes(raw)
        try:
            ctl=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            ctl.settimeout(3)
            ctl.connect(str(MON))
            ctl.recv(4096)
            ctl.sendall(f"screendump {OUT/'screen.ppm'}\n".encode())
            ctl.close()
        except Exception as exc:
            print("Screenshot error",exc,flush=True)
        proc.terminate()
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        client.close()
        server.shutdown()

text=bytes(raw).decode("utf-8",errors="replace")
(OUT/"result.txt").write_text(
    f"Source SHA: {SOURCE_SHA}\n"
    f"Source transfer: {'PASS' if marks.get('fetch-repository-source') else 'NOT CONFIRMED'}\n"
    f"Native mk finished: {marks.get('native-amd64-mk', False)}\n"
    f"Native mk output status markers: {re.findall(r'PHASE3_MK_STATUS_\S+',text)}\n"
    "FRESH RYZOVA SOURCE KERNEL BOOT: NOT ATTEMPTED. V3 PENDING.\n"
)
print("GUEST SERIAL TAIL:",text[-11000:],flush=True)
if not marks.get("native-amd64-mk"):
    print("FAIL: native compilation stage not completed",file=sys.stderr)
    sys.exit(1)
# Plan9 rc $status is empty on success; the shell prints PHASE3_MK_STATUS_.
if not re.search(r"(?:^|\r?\n)PHASE3_MK_STATUS_\s*(?:\r?\n)",text):
    print("FAIL: native mk returned an error or did not produce status marker",file=sys.stderr)
    sys.exit(1)
if re.search(r"(?:^|\r?\n)ls:.*9pc64",text):
    print("FAIL: expected AMD64 kernel not found",file=sys.stderr)
    sys.exit(1)
if not marks.get("install-fresh-bootfile") or not re.search(
    r"(?:^|\r?\n)PHASE3_COPY_STATUS_\s*(?:\r?\n)", text
):
    print("FAIL: the fresh compiled binary was not byte-compared with the FAT bootfile",file=sys.stderr)
    sys.exit(1)
print("PASS: native mk returned success; new kernel copied to /n/9fat/9pc64 and cmp verified.",flush=True)

# Start a NEW QEMU process against the SAME disposable qcow2 overlay.
# plan9.ini reads "bootfile=9pc64", and we have verified by cmp that this
# filename contains the freshly compiled source-derived binary.
SER.unlink(missing_ok=True)
MON.unlink(missing_ok=True)
bootlog=bytearray()
bootstate=dict(bootargs=False,user=False,command=False)
with (OUT/"fresh-kernel-qemu-host.log").open("wb") as host:
    second=subprocess.Popen(cmd,stdout=host,stderr=subprocess.STDOUT)
    guest=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        for _ in range(300):
            try:
                guest.connect(str(SER))
                break
            except (FileNotFoundError,ConnectionRefusedError):
                time.sleep(.1)
        else:
            raise RuntimeError("fresh-boot serial socket unavailable")
        guest.setblocking(False)
        deadline=time.monotonic()+140
        while time.monotonic()<deadline:
            if second.poll() is not None:
                print("Fresh-kernel QEMU unexpectedly exited",flush=True)
                break
            ready,_,_=select.select([guest],[],[],.3)
            if ready:
                try: data=guest.recv(65536)
                except BlockingIOError: data=b""
                if data: bootlog.extend(data)
            tail=bytes(bootlog[-16000:])
            if b"bootargs is " in tail and not bootstate["bootargs"]:
                guest.sendall(b"\r")
                bootstate["bootargs"]=True
                print("FRESH KERNEL: bootargs prompt reached",flush=True)
            if (b"user[glenda]:" in tail or b"user:" in tail) and bootstate["bootargs"] and not bootstate["user"]:
                guest.sendall(b"glenda\r")
                bootstate["user"]=True
                print("FRESH KERNEL: userspace login reached",flush=True)
            if b"term%" in tail and bootstate["user"] and not bootstate["command"]:
                guest.sendall(b"cat '#Z/version'; cat '#Z/foundation'; cat '#Z/abi'; echo RYZOVA_FRESH_KERNEL | tr A-Z a-z\r")
                bootstate["command"]=True
                print("FRESH KERNEL: rc probe sent",flush=True)
            if re.search(rb"(?:\r?\n)ryzova_fresh_kernel(?:\r?\n)",bytes(bootlog)):
                print("FRESH KERNEL: native rc probe produced expected output",flush=True)
                break
    finally:
        (OUT/"fresh-boot-serial.log").write_bytes(bootlog)
        second.terminate()
        try: second.wait(timeout=8)
        except subprocess.TimeoutExpired: second.kill()
        guest.close()

boottext=bytes(bootlog).decode("utf-8",errors="replace")
fresh_rc_ok=bool(re.search(rb"(?:\r?\n)ryzova_fresh_kernel(?:\r?\n)",bytes(bootlog)))
(OUT/"result.txt").write_text(
    f"Source SHA: {SOURCE_SHA}\n"
    f"Kernel source archive sha256: {archive_hash}\n"
    "V2 native source compilation: PASS\n"
    "New FAT bootfile byte-for-byte compared with compiled 9pc64: PASS\n"
    f"V3 bootargs prompt reached: {bootstate['bootargs']}\n"
    f"V3 rc userspace command verified: {fresh_rc_ok}\n"
)
print("FRESH BOOT SERIAL TAIL:",boottext[-7000:],flush=True)
if not (bootstate["bootargs"] and fresh_rc_ok):
    print("FAIL V3: no verifiable freshly built kernel-to-userspace boot",file=sys.stderr)
    sys.exit(1)
print("PASS V3: the new source-built 9pc64, installed to configured 9fat bootfile, booted into rc.",flush=True)

