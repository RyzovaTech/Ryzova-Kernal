#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M6.2 experimental AArch64 QEMU VirtIO network/storage *functional* probe.

Only actual guest HTTP payload delivery and guest/host shared ephemeral disk
write+read checks qualify. A boot banner, attached PCI device, print/echo,
source compile or simulator-only fixture can never qualify I/O. This guest
is disposable; outbound traffic is restricted to one localhost fixture.
"""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import threading
import time

SCHEMA = "ryzova-m6-arm64-virtio-functional/v1"
NET_GUEST_PORT = 18088
MAX_SERIAL = 2 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def standalone_marker(data: bytes, marker: str) -> bool:
    """Never count a shell's echoed command line as executed proof."""
    return re.search(
        rb"(?:^|\r?\n)" + re.escape(marker.encode()) + rb"(?:\r?\n|$)",
        data,
    ) is not None


def classify(serial: bytes, *, net_payload: bytes, disk_payload: bytes,
             host_get_count: int, host_disk_prefix: bytes,
             stages: set[int], shell_reached: bool) -> dict:
    net_hash = sha256(net_payload).encode()
    disk_hash = sha256(disk_payload).encode()
    # The dynamic SHA is not included in any command sent to the guest.
    net_guest_hash = bool(re.search(rb"(?:^|\r?\n)" + net_hash +
                                    rb"(?:[ \t][^\r\n]*)?(?:\r?\n)", serial))
    disk_guest_hash = bool(re.search(rb"(?:^|\r?\n)" + disk_hash +
                                     rb"(?:[ \t][^\r\n]*)?(?:\r?\n)", serial))
    net_ok = (shell_reached and 1 in stages and host_get_count >= 1
              and net_guest_hash)
    disk_status = standalone_marker(serial, "M6_DISK_WRITE_STATUS_")
    disk_ok = (shell_reached and 2 in stages and 3 in stages
               and disk_status and disk_guest_hash
               and host_disk_prefix == disk_payload)
    return {
        "guest_shell_reached": bool(shell_reached),
        "http_guest_request_observed": host_get_count >= 1,
        "guest_network_digest_verified": net_guest_hash,
        "guest_disk_write_status_ok": disk_status,
        "guest_disk_read_digest_verified": disk_guest_hash,
        "host_ephemeral_disk_write_verified": host_disk_prefix == disk_payload,
        "arm64_virtio_network_verified": bool(net_ok),
        "arm64_virtio_storage_verified": bool(disk_ok),
    }


def _guest_commands(disk_payload: bytes):
    token = disk_payload.decode("ascii").rstrip("\n")
    return [
        "ip/ipconfig -d ether /net/ether0; webfs; echo M6_STAGE_0",
        f"hget http://10.0.2.100:{NET_GUEST_PORT}/m6-probe | sha1sum -2 256; echo M6_STAGE_1",
        f"echo {token} > /dev/sd01/data; echo M6_DISK_WRITE_STATUS_$status; echo M6_STAGE_2",
        f"dd -if /dev/sd01/data -of /tmp/m6-disk-read -bs 1 -count {len(disk_payload)} > /tmp/m6-dd.log >[2=1]; sha1sum -2 256 /tmp/m6-disk-read; echo M6_STAGE_3",
    ]


def run_probe(kernel: Path, source_sha: str, expected_digest: str,
              out: Path, *, root_overlay: Path | None = None,
              timeout_seconds: int = 100) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "schema": SCHEMA, "source_sha": source_sha,
        "expected_uimage_sha256": expected_digest,
        "verified_uimage_sha256": False,
        "qemu_virtio_devices_attached": False,
        "root_disk_copy_on_write": False,
        "guest_shell_reached": False,
        "http_guest_request_observed": False,
        "guest_network_digest_verified": False,
        "guest_disk_write_status_ok": False,
        "guest_disk_read_digest_verified": False,
        "host_ephemeral_disk_write_verified": False,
        "arm64_virtio_network_verified": False,
        "arm64_virtio_storage_verified": False,
        "physical_hardware_certified": False,
        "newly_certified_physical_models": 0,
        "release_status": "blocked",
        "outcome": "not-tested",
    }
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        result["outcome"] = "invalid-source-sha"
    elif not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        result["outcome"] = "invalid-kernel-digest"
    elif not kernel.is_file() or sha256(kernel.read_bytes()) != expected_digest:
        result["outcome"] = "kernel-digest-mismatch"
    elif root_overlay is None or not root_overlay.is_file():
        result["outcome"] = "rootfs-disk-missing"
    else:
        result["verified_uimage_sha256"] = True
        net_payload = ("RYZOVA_M6_NET_DATA_" + source_sha + "\n").encode()
        disk_payload = ("RYZOVA_M6_DISK_" + source_sha[:16] + "\n").encode()
        request_count = [0]

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/m6-probe":
                    self.send_error(404)
                    return
                request_count[0] += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(net_payload)))
                self.end_headers()
                self.wfile.write(net_payload)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory(prefix="ryzova-m6-virtio-") as td:
            disk = Path(td) / "guest-only-scsi.img"
            # The source-built 9front root filesystem is an AMD64 *build*
            # guest image, not a bootable ARM64 QEMU firmware image. Mount its
            # architecture-neutral hjfs root through VirtIO-SCSI; use the
            # already source-built AArch64 uImage supplied separately.
            # Never write to the original evidence disk: COW on an overlay.
            root_disk = Path(td) / "arm64-root-cow.qcow2"
            subprocess.run([
                "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                "-b", str(root_overlay.resolve()), str(root_disk),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            result["root_disk_copy_on_write"] = True
            with disk.open("wb") as d:
                d.truncate(8 * 1024 * 1024)
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server_thread = threading.Thread(target=httpd.serve_forever,
                                             daemon=True)
            server_thread.start()
            host_port = httpd.server_address[1]
            cmd = [
                "qemu-system-aarch64", "-machine", "virt,highmem=off,gic-version=3",
                "-cpu", "cortex-a57", "-smp", "2", "-m", "2048",
                "-display", "none", "-nographic", "-monitor", "none",
                "-kernel", str(kernel), "-no-reboot",
                "-netdev", f"user,id=m6net,restrict=on,guestfwd=tcp:10.0.2.100:{NET_GUEST_PORT}-tcp:127.0.0.1:{host_port}",
                "-device", "virtio-net-pci,netdev=m6net",
                "-device", "virtio-scsi-pci,id=m6scsi",
                # Boot root must enumerate as sd00; scratch as sd01.
                "-drive", f"if=none,id=m6root,format=qcow2,file={root_disk}",
                "-device", "scsi-hd,drive=m6root",
                "-drive", f"if=none,id=m6disk,format=raw,file={disk}",
                "-device", "scsi-hd,drive=m6disk",
            ]
            raw = bytearray()
            stages: set[int] = set()
            shell = False
            commands = _guest_commands(disk_payload)
            stage = 0
            sent = False
            bootargs_answered = False
            user_answered = False
            proc = None
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0)
                start = time.monotonic()
                while time.monotonic() - start < timeout_seconds:
                    if proc.poll() is not None:
                        break
                    if proc.stdout is None:
                        break
                    ready, _, _ = select.select([proc.stdout], [], [], 0.25)
                    if ready:
                        data = os.read(proc.stdout.fileno(), 65536)
                        if not data:
                            break
                        if len(raw) < MAX_SERIAL:
                            raw.extend(data[:MAX_SERIAL-len(raw)])
                    tail = bytes(raw[-16000:])
                    if b"bootargs is " in tail and not bootargs_answered:
                        proc.stdin.write(b"\r")
                        proc.stdin.flush()
                        bootargs_answered = True
                    if (b"user[glenda]:" in tail or b"user:" in tail) and not user_answered:
                        proc.stdin.write(b"glenda\r")
                        proc.stdin.flush()
                        user_answered = True
                    if b"term%" in tail:
                        shell = True
                    if shell and stage < len(commands):
                        if not sent:
                            proc.stdin.write((commands[stage]+"\r").encode())
                            proc.stdin.flush()
                            sent = True
                        if standalone_marker(bytes(raw), f"M6_STAGE_{stage}"):
                            stages.add(stage)
                            stage += 1
                            sent = False
                            if stage == len(commands):
                                break
            finally:
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    if proc.stdin:
                        proc.stdin.close()
                    if proc.stdout:
                        proc.stdout.close()
                httpd.shutdown()
                httpd.server_close()
                server_thread.join(timeout=5)
                (out / "m6-arm64-virtio-serial.log").write_bytes(raw)
                with disk.open("rb") as f:
                    observed_prefix = f.read(len(disk_payload))
                result["qemu_virtio_devices_attached"] = bool(proc and
                    b"qemu-system-aarch64: " not in raw)
                result.update(classify(
                    bytes(raw), net_payload=net_payload,
                    disk_payload=disk_payload,
                    host_get_count=request_count[0],
                    host_disk_prefix=observed_prefix,
                    stages=stages, shell_reached=shell,
                ))
                result["completed_guest_stages"] = sorted(stages)
                result["host_fixture_requests"] = request_count[0]
                result["outcome"] = ("guest-virtio-io-observed"
                    if result["arm64_virtio_network_verified"]
                    and result["arm64_virtio_storage_verified"]
                    else "guest-virtio-io-incomplete")
    (out / "m6-arm64-virtio-probe.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return result
