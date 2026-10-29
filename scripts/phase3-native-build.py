#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build imported Ryzova source inside a disposable 9front AMD64 QEMU guest.

Strict gate: an official prebuilt guest boot and source parity are NOT the same as
a successful fresh build. This workflow stops before claiming V3 until V2 works.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import threading
import time

from m2_qemu_probe import run_probe
from qemu_control import control_socket, control_address, serial_option, monitor_option
from phase4_1_stability import STAGES as PHASE41_STAGES, check_stability_serial
from phase4_5_stress import STAGES as PHASE45_STAGES, check_extended_serial
from phase6_native_9p import guest_commands, inspect_native_9p_serial, payload_for_commit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture
from phase7_secure_closeout import gateway_metrics_report
from phase7_native_guest_tls import commands as native_tls_commands, inspect as inspect_native_tls
from phase8_guest_identity import commands as guest_identity_commands, inspect as inspect_guest_identity
from phase9_compact_native import commands as compact_commands, fixtures as compact_fixtures, inspect as inspect_compact
from phase9_linux_environment import commands as environment_commands, fixtures as environment_fixtures, payload as environment_payload, inspect as inspect_environment
from phase9_process import build as build_process, commands as process_commands, inspect as inspect_process
from phase9_busybox import fetch as fetch_busybox, commands as busybox_commands, inspect as inspect_busybox
from phase9_shell import fetch as fetch_shell, commands as shell_commands, inspect as inspect_shell
from phase9_jobs import fixtures as jobs_fixtures, commands as jobs_commands, inspect as inspect_jobs
from phase9_vfs import fixtures as vfs_fixtures, commands as vfs_commands, inspect as inspect_vfs
from phase9_runtime import fixtures as runtime_fixtures, commands as application_commands, inspect as inspect_application
from phase9_threads import fixtures as thread_fixtures, commands as thread_commands, inspect as inspect_threads
from phase9_sockets import fixtures as socket_fixtures, commands as socket_commands, inspect as inspect_sockets
from phase9_persistence import fixtures as persistence_fixtures, commands as persistence_commands, inspect as inspect_persistence
OUT = ROOT / "artifacts" / "phase3"
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "network-probe.txt").write_text("RYZOVA_NETWORK_DATA\n")
SER = OUT / "serial.sock"
MON = OUT / "monitor.sock"
ARCHIVE = OUT / "kernel-source.tar.gz"
GUEST_IMAGE = Path(sys.argv[1]).resolve()
SOURCE_SHA = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()

subprocess.run(["tar", "--format=ustar", "--transform=s,^ryzova/compat/linux,sys/src/cmd/compact-linux,", "-czf", str(ARCHIVE), "-C", str(ROOT), "sys/src/9", "sys/include", "amd64/include", "arm64/include", "sys/src/cmd/nusb", "ryzova/compat/linux"], check=True)
archive_hash = subprocess.check_output(["sha256sum", str(ARCHIVE)], text=True).split()[0]
(OUT / "source-provenance.txt").write_text(
    f"Ryzova source commit: {SOURCE_SHA}\nKernel and nusb source archive sha256: {archive_hash}\n"
    "Archive includes kernel, nusb user-space source, sys/include and amd64/include from exact commit.\n"
)
print("SOURCE_SHA", SOURCE_SHA, "ARCHIVE_SHA256", archive_hash, flush=True)
fetch_busybox(OUT)
fetch_shell(OUT)
jobs_fixture_sha256=jobs_fixtures(OUT)
vfs_fixture_sha256=vfs_fixtures(OUT)
runtime_fixture_sha256=runtime_fixtures(OUT,SOURCE_SHA)
thread_fixture_sha256=thread_fixtures(OUT,SOURCE_SHA)
socket_fixture_sha256=socket_fixtures(OUT,SOURCE_SHA)
persistence_fixture_sha256=persistence_fixtures(OUT,SOURCE_SHA)
process_elf_sha256 = build_process(OUT / "process-compiled.elf")
(OUT / "flex-input.bin").write_bytes(environment_payload(SOURCE_SHA))
for name, data in environment_fixtures().items():
    (OUT / f"flex-{name}.elf").write_bytes(data)
for name, data in compact_fixtures(SOURCE_SHA).items():
    (OUT / f"compact-{name}.elf").write_bytes(data)

class LocalHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(OUT), **kwargs)
    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args, flush=True)

server = http.server.ThreadingHTTPServer(("127.0.0.1", 8000), LocalHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()

cmd = [
    "qemu-system-x86_64",
    "-machine", "pc,accel=tcg", "-cpu", "qemu64", "-m", "2048", "-smp", "2",
    "-device", "virtio-scsi-pci,id=scsi",
    "-drive", f"if=none,id=vd0,file={GUEST_IMAGE},format=qcow2",
    "-device", "scsi-hd,drive=vd0",
    "-device", "virtio-net-pci,netdev=n0", "-netdev", "user,id=n0",
    "-vga", "std", "-display", "none",
    "-chardev", serial_option(SER),
    "-serial", "chardev:uart",
    "-monitor", monitor_option(MON),
    "-no-reboot", "-no-shutdown",
]
# M1 QEMU regression exposes generic emulated xHCI keyboard/mouse devices.
# This is NOT equivalent to physical USB HID qualification.
if (ROOT / "sys/src/cmd/nusb/lib/m1class.c").is_file():
    cmd += [
        "-device", "qemu-xhci,id=m1xhci",
        "-device", "usb-kbd,bus=m1xhci.0",
        "-device", "usb-mouse,bus=m1xhci.0",
    ]
# The 9front rc shell is used for ALL target compilation, not Linux gcc/make.
stages = [
    ("guest-network", "ip/ipconfig -d ether /net/ether0; webfs; echo PHASE3_END_0"),
    ("fetch-repository-source",
     "hget http://10.0.2.2:8000/kernel-source.tar.gz > /tmp/kernel-source.tar.gz; "
     "ls -l /tmp/kernel-source.tar.gz; echo PHASE3_END_1"),
    ("install-exact-kernel-source",
     "cd /; mkdir -p /sys/src/cmd/compact-linux; tar xzf /tmp/kernel-source.tar.gz; "
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
     "ls -l /n/9fat/9pc64; sha1sum -2 256 9pc64; sha1sum -2 256 /n/9fat/9pc64; echo PHASE3_END_5"),
]
# M1 class drivers must compile with the actual Plan 9 toolchain, not only
# GCC. Keep the 5 builds separate to avoid overlong rc serial commands.
m1_native_components = ("lib", "kb", "disk", "audio", "ether") if (
    ROOT / "sys/src/cmd/nusb/lib/m1class.c"
).is_file() else ()
for component in m1_native_components:
    stageindex = len(stages)
    stages.append((
        "m1-usb-" + component,
        "cd /sys/src/cmd/nusb/" + component +
        "; mk " + ("install" if component != "lib" else "") +
        " > /tmp/m1-" + component + ".log >[2=1]; echo M1_" +
        component.upper() + "_STATUS_$status; tail -n 15 /tmp/m1-" +
        component + ".log; echo PHASE3_END_" + str(stageindex)
    ))

index = len(stages)
stages.append(("compact-linux-native",
    "cd /sys/src/cmd/compact-linux && mk install > /tmp/compact-build.log >[2=1] "
    "&& test -s /amd64/bin/compact-linux && echo COMPACT_NATIVE_BUILD_OK; "
    "tail -n 30 /tmp/compact-build.log; "
    "echo PHASE3_END_" + str(index)))

# M5.1 native ARM64 cross-build in an *actual* 9front AMD64 guest.
# Reuse 7c/7l and installed cross-architecture libraries only if available.
# Unlike a GCC helper test, this checks the real ARM64 Plan 9 kernel target.
m5_arm64_native = (ROOT / "sys/src/9/arm64/m5ecam.c").is_file()
if m5_arm64_native:
    index=len(stages)
    stages.append(("m5-arm64-native",
        "cd /sys/src/9/arm64; 7c -o /tmp/m5ecam.7 m5ecam.c; "
        "echo M5_ARM64_7C_STATUS_$status; ls -l /tmp/m5ecam.7; "
        "mk 9qemu > /tmp/m5-arm64-native.log >[2=1]; "
        "echo M5_ARM64_MK_STATUS_$status; tail -n 20 /tmp/m5-arm64-native.log; "
        "ls -l 9qemu; echo PHASE3_END_" + str(index)))

index = len(stages)
stages.append(("compact-linux-service",
    "cd /sys/src/cmd/compact-linux/service && mk install > /tmp/compact-fs.log >[2=1] "
    "&& echo COMPACT_SERVICE_BUILD_OK; tail -n 30 /tmp/compact-fs.log; echo PHASE3_END_" + str(index)))

# The source-built kernel is copied through FAT, but user-space binaries are
# installed on hjfs. Flush that filesystem before terminating this QEMU process.
index = len(stages)
stages.append(("flush-native-filesystem",
    "echo sync >> /srv/hjfs.cmd && sleep 3 && echo COMPACT_FS_SYNC_OK; "
    "echo PHASE3_END_" + str(index)))

raw=bytearray()
session = dict(bootargs=False, user=False, shell=False, stage=0, sent=False, final=False)
marks = {}
with (OUT/"host.log").open("wb") as host:
    proc=subprocess.Popen(cmd,stdout=host,stderr=subprocess.STDOUT)
    client=control_socket(SER)
    try:
        for _ in range(300):
            try:
                client.connect(control_address(SER))
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
                    if ix==len(stages)-1:
                        session["final"]=True
                        break
                if time.monotonic()-stage_start>380:
                    print("STAGE TIMEOUT",ix,label,flush=True)
                    break
        print("Stages:",marks,flush=True)
    finally:
        (OUT/"serial.log").write_bytes(raw)
        try:
            ctl=control_socket(MON)
            ctl.settimeout(3)
            ctl.connect(control_address(MON))
            ctl.recv(4096)
            ctl.sendall(f"screendump {OUT/'screen.ppm'}\n".encode())
            ctl.close()
        except Exception as exc:
            print("Screenshot error",exc,flush=True)
        proc.terminate()
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        client.close()

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
if not re.search(rb"(?:^|\r?\n)COMPACT_SERVICE_BUILD_OK(?:\r?\n|$)", bytes(raw)):
    print("FAIL: native Compact discovery service did not compile/install", file=sys.stderr)
    sys.exit(1)

if not marks.get("flush-native-filesystem"):
    print("FAIL: native filesystem sync stage did not complete", file=sys.stderr)
    sys.exit(1)

if not re.search(rb"(?:^|\r?\n)COMPACT_NATIVE_BUILD_OK(?:\r?\n|$)", bytes(raw)):
    print("FAIL: native Compact application did not compile/install", file=sys.stderr)
    print(bytes(raw[-16000:]).decode("utf-8", errors="replace"), flush=True)
    sys.exit(1)

if not marks.get("install-fresh-bootfile") or not re.search(
    r"(?:^|\r?\n)PHASE3_COPY_STATUS_\s*(?:\r?\n)", text
):
    print("FAIL: the fresh compiled binary was not byte-compared with the FAT bootfile",file=sys.stderr)
    sys.exit(1)
# No source-only approval when a native user-space class driver fails.
for component in m1_native_components:
    marker = "M1_" + component.upper() + "_STATUS_"
    if not marks.get("m1-usb-" + component) or not re.search(
        r"(?:^|\r?\n)" + marker + r"\s*(?:\r?\n)", text
    ):
        print("FAIL M1 native user-space build:", component, file=sys.stderr)
        sys.exit(1)
if m5_arm64_native:
    # M5.1 has a two-part gate: a cross-architecture native 7c compiler
    # can prove C source compatibility, but it cannot stand in for a
    # linked and booted ARM64 kernel.
    cross_ok = bool(marks.get("m5-arm64-native") and re.search(
        r"(?:^|\r?\n)M5_ARM64_7C_STATUS_\s*(?:\r?\n)", text
    ) and not re.search(r"(?:^|\r?\n)ls:.*m5ecam.7", text))
    arm64_link_ok = bool(re.search(
        r"(?:^|\r?\n)M5_ARM64_MK_STATUS_\s*(?:\r?\n)", text
    ) and not re.search(r"(?:^|\r?\n)ls:.*9qemu", text))
    (OUT / "m5-arm64-native-build.json").write_text(json.dumps({
        "source_sha": SOURCE_SHA,
        "cross_compiler_7c": "pass" if cross_ok else "fail",
        "arm64_kernel_link": "pass" if arm64_link_ok else "blocked",
        "arm64_qemu_boot": "not-tested",
        "full_m5_1_complete": False,
        "known_dep_blocker": None if arm64_link_ok else
            "ARM64 bootfs userspace /arm64/bin/paqfs not installed in AMD64 toolchain guest",
    }, indent=2) + "\n")
    if not cross_ok:
        print("FAIL M5.1: ARM64 Plan 9 native 7c source compile failed",
              file=sys.stderr)
        sys.exit(1)
    print("M5.1 ARM64 7c cross-compile PASS; full ARM64 kernel link:",
          "PASS" if arm64_link_ok else "BLOCKED (missing guest userspace)",
          flush=True)
print("PASS: native mk returned success; new kernel copied to /n/9fat/9pc64 and cmp verified.",flush=True)

# M2 tests the two emulated PCI chipsets ONLY in a later isolated QEMU
# process, preserving the original VirtIO network for baseline 9P/HTTP checks.
m2_enabled = (ROOT / "ryzova/drivers/m2-chipset-families.json").is_file()
fresh_cmd = list(cmd)
# QEMU guest -> plaintext CI-host 9P gateway -> pinned mutual TLS 1.3
# -> separate, read-only 9P2000 localhost peer. Public fixture only.
tls_fixture = Ephemeral9PTLSFixture(payload_for_commit(SOURCE_SHA), gateway_port=15640, guest_tls_port=15641,
    enable_guest_identity=True, authenticated_guest_port=15642).start()
guest_cert_pin = tls_fixture.guest_cert_sha256
guest_client_pin = tls_fixture.guest_client_pin
credential_paths = [OUT / "guest-identity-cert.pem", OUT / "guest-identity-key.pem"]
for original, target in zip((tls_fixture.guest_client_cert, tls_fixture.guest_client_key), credential_paths):
    shutil.copyfile(original, target)
    target.chmod(0o600)
print("PHASE7 native read-only 9P gateway and mutual TLS peer started", flush=True)

# Start a NEW QEMU process against the SAME disposable qcow2 overlay.
# plan9.ini reads "bootfile=9pc64", and we have verified by cmp that this
# filename contains the freshly compiled source-derived binary.
SER.unlink(missing_ok=True)
MON.unlink(missing_ok=True)
bootlog=bytearray()
runtime_commands=[
    "mkdir -p /tmp/ryzova-9p; ramfs -m /tmp/ryzova-9p; echo RYZOVA_RUNTIME_STAGE_0",
    "echo RYZOVA_9P_DATA > /tmp/ryzova-9p/probe; grep RYZOVA_9P_DATA /tmp/ryzova-9p/probe > /dev/null && echo RYZOVA_9P_OK; echo RYZOVA_RUNTIME_STAGE_1",
    "9fs 9fat; grep 'bootfile=9pc64' /n/9fat/plan9.ini > /dev/null && echo RYZOVA_STORAGE_OK; echo RYZOVA_RUNTIME_STAGE_2",
    "ip/ipconfig -d ether /net/ether0; webfs; sleep 4; echo RYZOVA_RUNTIME_STAGE_3",
    "hget http://10.0.2.2:8000/network-probe.txt | grep RYZOVA_NETWORK_DATA > /dev/null && echo RYZOVA_NETWORK_OK; echo RYZOVA_RUNTIME_STAGE_4",
] + [command for _, command in PHASE41_STAGES] + [command for _, command in PHASE45_STAGES] + [command for _, command in guest_commands()] + [command for _, command in native_tls_commands(tls_fixture.guest_cert_sha256)] + list(guest_identity_commands()) + compact_commands() + environment_commands() + process_commands(SOURCE_SHA) + busybox_commands(SOURCE_SHA) + shell_commands(SOURCE_SHA) + jobs_commands(SOURCE_SHA) + vfs_commands(SOURCE_SHA) + application_commands(SOURCE_SHA)[:-1] + [application_commands(SOURCE_SHA)[-1]+f"; echo RYZOVA_RUNTIME_STAGE_{136+len(application_commands(SOURCE_SHA))}"] + thread_commands(SOURCE_SHA)[:-1] + [thread_commands(SOURCE_SHA)[-1]+f"; echo RYZOVA_RUNTIME_STAGE_{136+len(application_commands(SOURCE_SHA))+len(thread_commands(SOURCE_SHA))}"] + socket_commands(SOURCE_SHA)[:-1] + [socket_commands(SOURCE_SHA)[-1]+f"; echo RYZOVA_RUNTIME_STAGE_{136+len(application_commands(SOURCE_SHA))+len(thread_commands(SOURCE_SHA))+len(socket_commands(SOURCE_SHA))}"] + persistence_commands(SOURCE_SHA)
bootstate=dict(bootargs=False,user=False,command=False,write_test=False,post_test=False,m0_probe_sent=False,runtime_test=False,runtime_stage=-1)
with (OUT/"fresh-kernel-qemu-host.log").open("wb") as host:
    second=subprocess.Popen(fresh_cmd,stdout=host,stderr=subprocess.STDOUT)
    guest=control_socket(SER)
    try:
        for _ in range(300):
            try:
                guest.connect(control_address(SER))
                break
            except (FileNotFoundError,ConnectionRefusedError):
                time.sleep(.1)
        else:
            raise RuntimeError("fresh-boot serial socket unavailable")
        guest.setblocking(False)
        deadline=time.monotonic()+330
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
                guest.sendall(b"cat '#Z/version'; cat '#Z/foundation'; cat '#Z/abi'; test -d /proc && echo RYZOVA_PROC_OK; test -d /net && echo RYZOVA_NET_OK; mkdir -p /tmp/ryzova-ns; bind '#Z' /tmp/ryzova-ns; cat /tmp/ryzova-ns/version; echo RYZOVA_FRESH_KERNEL | tr A-Z a-z\r")
                bootstate["command"]=True
                print("FRESH KERNEL: rc probe sent",flush=True)
            if re.search(rb"(?:\r?\n)ryzova_fresh_kernel(?:\r?\n)",bytes(bootlog)) and not bootstate["write_test"]:
                guest.sendall(b"echo NOT_ALLOWED > '#Z/version'\r")
                bootstate["write_test"]=True
                print("FRESH KERNEL: requested prohibited identity write",flush=True)
            if bootstate["write_test"] and b"can't create: #Z/version: permission denied" in bytes(bootlog) and not bootstate["post_test"]:
                guest.sendall(b"cat '#Z/version'; echo RYZOVA_RO_TEST_DONE | tr A-Z a-z\r")
                bootstate["post_test"]=True
                print("FRESH KERNEL: write denied; verifying device remains readable",flush=True)
            if re.search(rb"(?:\r?\n)ryzova_ro_test_done(?:\r?\n)",bytes(bootlog)) and not bootstate["m0_probe_sent"]:
                # Keep the existing namespace probe byte-for-byte intact. Send
                # a short PCI read-only diagnostic as its own serial command.
                tail=bytes(bootlog[-12000:])
                marker=b"ryzova_ro_test_done"
                pos=tail.rfind(b"\n"+marker+b"\r")
                if pos < 0:
                    pos=tail.rfind(b"\n"+marker+b"\n")
                if pos >= 0 and b"term%" in tail[pos+len(marker)+1:]:
                    time.sleep(.15)
                    guest.sendall(b"cat '#P/drivercandidates' | grep 'auto-bind=no' > /dev/null && echo RYZOVA_M0_PCI_OK\r")
                    bootstate["m0_probe_sent"]=True
                    print("FRESH KERNEL: independent M0 PCI read-only probe sent",flush=True)
            if bootstate["m0_probe_sent"] and not bootstate["runtime_test"]:
                tail=bytes(bootlog[-12000:])
                marker=b"RYZOVA_M0_PCI_OK"
                pos=tail.rfind(b"\n"+marker+b"\r")
                if pos < 0:
                    pos=tail.rfind(b"\n"+marker+b"\n")
                if pos >= 0 and b"term%" in tail[pos+len(marker)+1:]:
                    time.sleep(.15)
                    guest.sendall((runtime_commands[0]+"\r").encode())
                    bootstate["runtime_test"]=True
                    bootstate["runtime_stage"]=0
                    print("FRESH KERNEL: 9P/storage/network stage 0 sent",flush=True)
            elif bootstate["runtime_test"] and bootstate["runtime_stage"] < len(runtime_commands)-1:
                i=bootstate["runtime_stage"]
                # Await the rc prompt AFTER the output marker. A marker alone
                # may arrive before the shell is ready for the next serial line.
                marker=b"RYZOVA_RUNTIME_STAGE_"+str(i).encode()
                tail=bytes(bootlog[-12000:])
                pos=tail.rfind(b"\n"+marker+b"\r")
                if pos < 0:
                    pos=tail.rfind(b"\n"+marker+b"\n")
                if pos >= 0 and b"term%" in tail[pos+len(marker)+1:]:
                    time.sleep(.15)
                    bootstate["runtime_stage"]=i+1
                    guest.sendall((runtime_commands[i+1]+"\r").encode())
                    print("FRESH KERNEL: 9P/storage/network stage",i+1,"sent after rc prompt",flush=True)
            if re.search(rb"(?:\r?\n)FLEX_PERSISTENCE_DONE(?:\r?\n)",bytes(bootlog)):
                print("FRESH KERNEL: regression command sequence completed",flush=True)
                break
    finally:
        (OUT/"fresh-boot-serial.log").write_bytes(bootlog)
        second.terminate()
        try: second.wait(timeout=8)
        except subprocess.TimeoutExpired: second.kill()
        guest.close()
        server.shutdown()
        for path in credential_paths:
            path.unlink(missing_ok=True)
        guest_identity_metrics = {
            "sessions": tls_fixture.authenticated_guest_tls.authenticated_guest_sessions,
            "frames": tls_fixture.authenticated_guest_tls.forwarded_frames,
        }
        guest_tls_metrics = {
            "native_tls12_sessions": tls_fixture.guest_tls.tls12_sessions,
            "native_tls_9p_frames": tls_fixture.guest_tls.forwarded_frames,
            "upstream_tls13_sessions": tls_fixture.gateway.verified_tls_sessions,
        }
        tls_metrics = {
            "gateway_9p_frames": tls_fixture.gateway.forwarded_frames,
            "peer_9p_frames": tls_fixture.peer.frames,
            "tls_client_pinned_sessions": tls_fixture.gateway.verified_tls_sessions,
            "tls_server_pinned_sessions": tls_fixture.peer.secure_sessions,
            "denied_guest_writes": tls_fixture.gateway.denied_writes,
        }
        tls_fixture.close()

boottext=bytes(bootlog).decode("utf-8",errors="replace")
guest_identity_evidence = inspect_guest_identity(
    bytes(bootlog), SOURCE_SHA, guest_client_pin,
    guest_identity_metrics["sessions"], guest_identity_metrics["frames"])
(OUT / "phase8-guest-identity.json").write_text(
    json.dumps(guest_identity_evidence, indent=2, sort_keys=True) + "\n")
print("NATIVE GUEST IDENTITY", guest_identity_evidence["passed"], flush=True)
fresh_rc_ok=bool(re.search(rb"(?:\r?\n)ryzova_fresh_kernel(?:\r?\n)",bytes(bootlog)))
identity_ok=all(v in bytes(bootlog) for v in (b"Ryzova Kernel 0.1.0-dev", b"9front-derived", b"experimental-0"))
m0_pci_ok=bool(re.search(rb"(?:\r?\n)RYZOVA_M0_PCI_OK(?:\r?\n)", bytes(bootlog)))
# A separate disposable emulated PCI boot does not disturb baseline networking.
# Its output is captured as independent evidence and must contain both IDs.
# M4 additionally exercises AMD PCnet/RTL8139 enumeration at 384 MiB
# without changing the full-memory baseline. No functional NIC certification.
m4_legacy_enabled=(ROOT / "ryzova/drivers/m4-legacy-qualification.json").is_file()
m2_pci_ok=(not m2_enabled or run_probe(
    cmd, SER, MON, OUT, memory_mib=384 if m4_legacy_enabled else None
))
compact_evidence = inspect_compact(bytes(raw), bytes(bootlog), SOURCE_SHA)
(OUT / "phase9-compact-native.json").write_text(json.dumps(compact_evidence, indent=2) + "\n")
print("NATIVE COMPACT SUBSET", compact_evidence["passed"], flush=True)
environment_evidence = inspect_environment(bytes(raw), bytes(bootlog), SOURCE_SHA)
(OUT / "phase9-linux-environment.json").write_text(json.dumps(environment_evidence, indent=2) + "\n")
print("NATIVE LINUX FILE ENVIRONMENT", environment_evidence["passed"], flush=True)
application_evidence = inspect_application(bytes(bootlog), SOURCE_SHA, runtime_fixture_sha256)
(OUT / "phase9-linux-runtime.json").write_text(json.dumps(application_evidence, indent=2) + "\n")
print("NATIVE LINUX APPLICATION RUNTIME", application_evidence["passed"], flush=True)
thread_evidence=inspect_threads(bytes(bootlog),SOURCE_SHA,thread_fixture_sha256)
(OUT / "phase9-linux-threads.json").write_text(json.dumps(thread_evidence,indent=2)+"\n")
print("NATIVE LINUX THREADS",thread_evidence["passed"],flush=True)
socket_evidence=inspect_sockets(bytes(bootlog),SOURCE_SHA,socket_fixture_sha256)
(OUT / "phase9-linux-sockets.json").write_text(json.dumps(socket_evidence,indent=2)+"\n")
print("NATIVE LINUX SOCKETS",socket_evidence["passed"],flush=True)
persistence_evidence=inspect_persistence(bytes(bootlog),SOURCE_SHA,persistence_fixture_sha256)
(OUT / "phase9-linux-persistence.json").write_text(json.dumps(persistence_evidence,indent=2)+"\n")
print("NATIVE LINUX PERSISTENCE",persistence_evidence["passed"],flush=True)
vfs_evidence = inspect_vfs(bytes(bootlog), SOURCE_SHA, vfs_fixture_sha256)
(OUT / "phase9-linux-vfs.json").write_text(json.dumps(vfs_evidence, indent=2) + "\n")
print("NATIVE LINUX VFS", vfs_evidence["passed"], flush=True)
jobs_evidence = inspect_jobs(bytes(bootlog), SOURCE_SHA, jobs_fixture_sha256)
(OUT / "phase9-linux-jobs.json").write_text(json.dumps(jobs_evidence, indent=2) + "\n")
print("NATIVE LINUX JOBS", jobs_evidence["passed"], flush=True)
shell_evidence = inspect_shell(bytes(bootlog), SOURCE_SHA)
(OUT / "phase9-linux-shell.json").write_text(json.dumps(shell_evidence, indent=2) + "\n")
print("NATIVE LINUX SHELL", shell_evidence["passed"], flush=True)
busybox_evidence = inspect_busybox(bytes(bootlog), SOURCE_SHA)
(OUT / "phase9-linux-busybox.json").write_text(json.dumps(busybox_evidence, indent=2) + "\n")
print("NATIVE BUSYBOX APPLETS", busybox_evidence["passed"], flush=True)
process_evidence = inspect_process(bytes(raw), bytes(bootlog), SOURCE_SHA, process_elf_sha256)
(OUT / "phase9-linux-process.json").write_text(json.dumps(process_evidence, indent=2) + "\n")
print("NATIVE COMPILED LINUX PROCESS", process_evidence["passed"], flush=True)
if not process_evidence["passed"] and shutil.which("objdump"):
    subprocess.run(["objdump", "-d", str(OUT / "process-compiled.elf")], check=False)
runtime_ok=all(re.search(rb"(?:\r?\n)"+v+rb"(?:\r?\n)", bytes(bootlog)) for v in (b"RYZOVA_PROC_OK", b"RYZOVA_NET_OK")) and bytes(bootlog).count(b"Ryzova Kernel 0.1.0-dev") >= 2
# A failed output redirection causes Plan 9 rc to abort the current
# command line. Probe it independently, then ensure a fresh subsequent
# command can still read the device. Echoed input is not accepted as output.
regression_ok=all(re.search(rb"(?:\r?\n)"+v+rb"(?:\r?\n)",bytes(bootlog))
    for v in (b"RYZOVA_9P_OK",b"RYZOVA_STORAGE_OK",b"RYZOVA_NETWORK_OK",b"RYZOVA_RUNTIME_DONE"))
write_denied=(b"can't create: #Z/version: permission denied" in bytes(bootlog)
    and bool(re.search(rb"(?:\r?\n)ryzova_ro_test_done(?:\r?\n)",bytes(bootlog)))
    and bytes(bootlog).count(b"Ryzova Kernel 0.1.0-dev") >= 3)

# Phase 4.1: all positive markers must be standalone output lines from a
# freshly built QEMU guest; parsing command echo text is insufficient.
stability=check_stability_serial(bytes(bootlog))
(OUT/"phase4-1-stability.json").write_text(json.dumps(stability, indent=2, sort_keys=True) + "\n")
extended=check_extended_serial(bytes(bootlog))
(OUT/"phase4-5-stress.json").write_text(json.dumps(extended, indent=2, sort_keys=True) + "\n")
for label, ok in extended["checks"].items():
    print("PHASE4.5", "PASS" if ok else "FAIL", label, flush=True)
for label, ok in stability["checks"].items():
    print("PHASE4.1", "PASS" if ok else "FAIL", label, flush=True)
native_9p_evidence=inspect_native_9p_serial(bytes(bootlog),SOURCE_SHA,tls_metrics["gateway_9p_frames"])
guest_tls_evidence=inspect_native_tls(bytes(bootlog),SOURCE_SHA,guest_cert_pin,guest_tls_metrics)
(OUT/"phase7-native-guest-tls.json").write_text(json.dumps(guest_tls_evidence,indent=2,sort_keys=True)+"\n")
for label,ok in guest_tls_evidence["checks"].items():
    print("NATIVE GUEST TLS", "PASS" if ok else "FAIL",label,flush=True)
phase7_secure_evidence=gateway_metrics_report(SOURCE_SHA,tls_metrics,native_9p_evidence)
(OUT/"phase7-secure-bridge.json").write_text(json.dumps(phase7_secure_evidence,indent=2,sort_keys=True)+"\n")
for label, ok in phase7_secure_evidence["checks"].items():
    print("PHASE7 TLS GATEWAY", "PASS" if ok else "FAIL", label, flush=True)
(OUT/"phase6-native-9p.json").write_text(json.dumps(native_9p_evidence,indent=2,sort_keys=True)+"\n")
for label,ok in native_9p_evidence["checks"].items():
    print("PHASE6 NATIVE 9P", "PASS" if ok else "FAIL",label,flush=True)

(OUT/"result.txt").write_text(
    f"Source SHA: {SOURCE_SHA}\n"
    f"Kernel source archive sha256: {archive_hash}\n"
    "V2 native source compilation: PASS\n"
    "New FAT bootfile byte-for-byte compared with compiled 9pc64: PASS\n"
    f"V3 bootargs prompt reached: {bootstate['bootargs']}\n"
    f"V3 rc userspace command verified: {fresh_rc_ok}\n"
    f"V3 Ryzova identity device verified: {identity_ok}\n"
    f"V4 basic proc/net and per-process bind checks: {runtime_ok}\n"
    f"M0 native PCI candidate interface read: {m0_pci_ok}\n"
    f"M2 emulated AMD/Realtek exact PCI candidates detected: {m2_pci_ok}\n"
    f"V4 9P ramfs, 9fat and HTTP checks: {regression_ok}\n"
    f"V4.1 bounded memory/process/scheduler checks: {stability['passed']}\n"
    f"V4.5 bounded additional stress checks: {extended['passed']}\n"
    f"V6 source-built QEMU guest network 9P mount and SHA: {native_9p_evidence['passed']}\n"
    f"V7 native guest 9P via pinned mutual TLS host gateway: {phase7_secure_evidence['passed']}\n"
    f"V7 native 9front tlsclient pinned TLS1.2 9P: {guest_tls_evidence['passed']}\n"
)
print("FRESH BOOT SERIAL TAIL:",boottext[-7000:],flush=True)
if not (bootstate["bootargs"] and fresh_rc_ok and identity_ok and runtime_ok and m0_pci_ok and m2_pci_ok and write_denied and regression_ok and stability["passed"] and extended["passed"] and native_9p_evidence["passed"] and phase7_secure_evidence["passed"] and guest_tls_evidence["passed"] and guest_identity_evidence["passed"] and compact_evidence["passed"] and environment_evidence["passed"] and process_evidence["passed"] and busybox_evidence["passed"] and shell_evidence["passed"] and jobs_evidence["passed"] and vfs_evidence["passed"] and application_evidence["passed"] and thread_evidence["passed"] and socket_evidence["passed"] and persistence_evidence["passed"]):
    print("FAIL V3: no verifiable freshly built kernel-to-userspace boot",file=sys.stderr)
    sys.exit(1)
print("PASS native 9front tlsclient pinned TLS1.2 guest ingress and host mutual TLS1.3 peer; native 9P guest SHA, M2/M4 preserved.",flush=True)

