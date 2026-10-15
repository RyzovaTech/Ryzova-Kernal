#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Extract a source-built 9front/Ryzova boot kernel from a QEMU disk overlay.

Do not publish the binary until third-party redistribution is cleared.
An independent host SHA256 must equal the 9front guest's SHA256 of both
the freshly built /sys/src/9/pc64/9pc64 and /n/9fat/9pc64.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "phase3"
SERIAL = OUT / "serial.log"
SOURCE = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()

def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=True)

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def candidate_offsets(image: Path) -> list[int]:
    # The 9front guest exposes a FAT 9fat boot partition. Locate its BPB on
    # a converted sparse raw disk rather than making assumptions about MBR.
    found: list[int] = []
    with image.open("rb") as fh:
        for off in range(0, 128 * 1024 * 1024, 512):
            fh.seek(off)
            b = fh.read(512)
            if len(b) < 512:
                break
            if (b[:1] in (b"\\xeb", b"\\xe9")
                and b[510:512] == b"\\x55\\xaa"
                and (b[54:62].startswith(b"FAT") or b[82:90].startswith(b"FAT"))):
                found.append(off)
    return found

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: extract-9pc64.py <qemu-qcow2-overlay>", file=sys.stderr)
        return 2
    overlay = Path(sys.argv[1]).resolve()
    log = SERIAL.read_text(encoding="utf-8", errors="replace")
    # The file checksum is read only from the *first*, source-compilation
    # QEMU boot, before the second boot starts.
    before_second_boot = log
    checks = re.findall(
        r"(?m)^([0-9a-f]{64})\\s+(9pc64|/n/9fat/9pc64)\\s*$",
        before_second_boot
    )
    expected = {}
    for hash_, path in checks:
        expected[path] = hash_
    if set(expected) != {"9pc64", "/n/9fat/9pc64"}:
        raise RuntimeError(f"Missing guest SHA256 proof for both built and installed kernel: {expected}")
    if expected["9pc64"] != expected["/n/9fat/9pc64"]:
        raise RuntimeError("Guest source-built kernel and installed bootfile SHA256 differ")
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ryzova-extract-") as td:
        raw = Path(td) / "disk.raw"
        kernel = OUT / "9pc64"
        try:
            # File is sparse; virtual disk size is not the consumed host space.
            run("qemu-img", "convert", "-O", "raw", "-S", "4k", str(overlay), str(raw))
            offsets = candidate_offsets(raw)
            print("FAT candidate offsets:", offsets, flush=True)
            copied = False
            for off in offsets:
                p = subprocess.run(
                    ["mcopy", "-o", "-i", f"{raw}@@{off}", "::9pc64", str(kernel)],
                    capture_output=True, text=True
                )
                if p.returncode == 0 and kernel.is_file() and kernel.stat().st_size > 100_000:
                    print("Extracted kernel at FAT partition offset:", off, flush=True)
                    copied = True
                    break
            if not copied:
                raise RuntimeError(f"Could not extract /9pc64 from FAT candidates: {offsets}")
            host_digest = digest(kernel)
            if host_digest != expected["9pc64"]:
                raise RuntimeError(f"Guest/host SHA256 mismatch: guest={expected['9pc64']} host={host_digest}")
            (OUT / "9pc64.sha256").write_text(f"{host_digest}  9pc64\\n")
            record = {
                "source_commit": SOURCE,
                "compiled_kernel_path_in_guest": "/sys/src/9/pc64/9pc64",
                "bootfile_path_in_guest": "/n/9fat/9pc64",
                "guest_compiled_sha256": expected["9pc64"],
                "guest_installed_sha256": expected["/n/9fat/9pc64"],
                "independently_extracted_host_sha256": host_digest,
                "binary_size_bytes": kernel.stat().st_size,
                "verification": "three SHA256 digests equal; QEMU boot separately verified",
                "distribution_status": "BLOCKED pending reviewed scoped redistribution rights",
            }
            (OUT / "kernel-provenance.json").write_text(json.dumps(record, indent=2) + "\\n")
            print("PASS: source-built, installed and independently extracted kernel SHA256 match:", host_digest, flush=True)
        finally:
            # Never upload the kernel to a public workflow artifact while
            # redistribution rights of embedded 9front payload are unresolved.
            kernel.unlink(missing_ok=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
