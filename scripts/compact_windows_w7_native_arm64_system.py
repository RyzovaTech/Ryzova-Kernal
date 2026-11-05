# SPDX-License-Identifier: AGPL-3.0-only
"""W7: independently try building and booting real Ryzova ARM64 QEMU kernel.

This is NOT Linux ARM64 qemu-user. It uses the same byte-pinned 9front
AMD64 build guest as the already accepted W6 source build, and runs 9front
7c/7l on actual, source-hashed Ryzova ARM64 kernel sources. A second,
different qemu-system-aarch64 VM must boot the produced 9qemu.u binary.
No result claims Windows ARM64 application compatibility or W9 hardware.

There is no fallback to a downloaded prebuilt ARM64 kernel. All images
must be independently hashed on producer and consumer sides.
"""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import threading

from compact_windows_w6_native import (
    ROOT, PIN, bootstrap_provenance, digest, session, standalone
)

SCHEMA = "compact-windows-w7-native-arm64-system-boot/v1"
BOOT_FILES = ("sys/src/9/arm64/main.c", "sys/src/9/arm64/qemu",
              "sys/src/9/arm64/mkfile", "sys/src/9/arm64/l.s",
              "sys/src/9/arm64/bootargs.c")
SRC_PREFIXES = ("sys/src/9/arm64/", "sys/src/9/port/",
                "sys/src/9/boot/", "sys/include/", "arm64/include/")
MAX_ARCHIVE = 40 * 1024 * 1024
MAX_KERNEL = 32 * 1024 * 1024
BOOT_TIME = 100


def inventory():
    found = subprocess.check_output(
        ["git", "ls-files", "--", *SRC_PREFIXES], cwd=ROOT,
        timeout=20).decode("utf-8").splitlines()
    files = sorted(p for p in found if any(p.startswith(x) for x in SRC_PREFIXES))
    if len(files) < 350 or not set(BOOT_FILES).issubset(files):
        raise ValueError("incomplete source-locked ARM64 kernel and port tree")
    output = {}
    for name in files:
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("non-regular source tree entry: " + name)
        output[name] = digest(path)
    return output


def bundle(path, items):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # The original Plan 9 tar extractor reads USTAR, not arbitrary GNU PAX.
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(items):
            archive.add(ROOT / name, arcname=name, recursive=False)
    if not 128 <= path.stat().st_size <= MAX_ARCHIVE:
        raise ValueError("unbounded ARM64 source bundle")
    return digest(path)


def read_guest_kernel(qcow, wanted, destination):
    """Independently extract 9qemu.u from the actual x86 guest's FAT image."""
    if not re.fullmatch(r"[0-9a-f]{64}", wanted):
        raise ValueError("invalid expected native kernel SHA")
    with tempfile.TemporaryDirectory(prefix="ryzova-w7-arm64-fat-") as tmp:
        raw = Path(tmp) / "guest.img"
        subprocess.run(["qemu-img", "convert", "-O", "raw", "-S", "4k",
                        str(qcow), str(raw)], check=True, timeout=150)
        with raw.open("rb") as handle:
            for offset in range(0, 128 * 1024 * 1024, 512):
                handle.seek(offset)
                sector = handle.read(512)
                if len(sector) != 512:
                    break
                if (sector[:1] not in (b"\xeb", b"\xe9") or
                        sector[510:] != b"\x55\xaa" or
                        not (sector[54:62].startswith(b"FAT") or
                             sector[82:90].startswith(b"FAT"))):
                    continue
                with tempfile.TemporaryDirectory(prefix="ryzova-w7-arm64-extract-") as tmp2:
                    extracted = Path(tmp2) / "9qemu.u"
                    result = subprocess.run(
                        ["mcopy", "-o", "-i", str(raw) + "@@" + str(offset),
                         "::9qemu.u", str(extracted)], timeout=25,
                        capture_output=True)
                    if result.returncode == 0 and extracted.is_file():
                        if not 1024 <= extracted.stat().st_size <= MAX_KERNEL:
                            raise ValueError("ARM64 kernel size outside limit")
                        if digest(extracted) != wanted:
                            raise ValueError("guest ARM64 kernel checksum mismatch")
                        destination.write_bytes(extracted.read_bytes())
                        if digest(destination) != wanted:
                            raise ValueError("exported ARM64 kernel checksum mismatch")
                        return destination.stat().st_size
    raise ValueError("source-built ARM64 kernel not independently found in FAT")


def native_arm64_boot(binary, output):
    """Require two real ARM64 virtual-CPU boot markers, not just QEMU startup."""
    binary = Path(binary)
    if not binary.is_file() or not 1024 <= binary.stat().st_size <= MAX_KERNEL:
        raise ValueError("missing bounded source-built ARM64 kernel")
    output = Path(output)
    args = ["qemu-system-aarch64", "-machine", "virt,highmem=off",
            "-cpu", "cortex-a57", "-smp", "1", "-m", "1024",
            "-nographic", "-monitor", "none", "-no-reboot",
            "-kernel", str(binary)]
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=BOOT_TIME)
        serial = result.stdout
    except subprocess.TimeoutExpired as exc:
        serial = exc.stdout or b""
    if type(serial) is not bytes or len(serial) > 2 * 1024 * 1024:
        raise ValueError("ARM64 QEMU boot log unbounded")
    output.write_bytes(serial)
    # The first line comes from the actual Ryzova/9front arm64/main.c,
    # the second is a serial CPU initialization line from the same kernel.
    if (not re.search(rb"(?m)^\s*Plan 9\s*\r?$", serial) or
            not re.search(rb"(?m)^cpu0: 1000MHz QEMU\s*\r?$", serial)):
        raise ValueError("actual native ARM64 Ryzova kernel console not observed")
    return {
        "real_qemu_system_aarch64_boot_markers_verified": True,
        "boot_console_sha256": hashlib.sha256(serial).hexdigest(),
        "guest_architecture": "aarch64-system",
        "guest_cpu": "cortex-a57",
    }


def run(image, archive, result_dir):
    image = Path(image)
    archive = Path(archive)
    result_dir = Path(result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)
    base = bootstrap_provenance(image, archive)
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT,
        text=True, timeout=15).strip()
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("not exact source SHA")
    files = inventory()
    bundle_name = result_dir / "w7-native-arm64-source.tgz"
    compressed = bundle(bundle_name, files)
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(result_dir))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8000), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        commands = [
            "ip/ipconfig -d ether /net/ether0; webfs",
            "hget http://10.0.2.2:8000/w7-native-arm64-source.tgz > /tmp/w7-a64.tgz; sha1sum -2 256 /tmp/w7-a64.tgz",
            "ls /amd64/bin/7c /amd64/bin/7l /arm64/mkfile /arm64/lib/libc.a && echo CW_W7_A64_CROSS_TOOLS_OK",
            "cd /; tar xzf /tmp/w7-a64.tgz && echo CW_W7_A64_SOURCES_OK",
            "cd /sys/src/9/arm64; objtype=arm64 mk > /tmp/w7-a64-kernel-build.log >[2=1] && echo CW_W7_A64_KERNEL_COMPILED; tail -n 28 /tmp/w7-a64-kernel-build.log",
            "9fs 9fat; cd /sys/src/9/arm64; cp 9qemu.u /n/9fat/9qemu.u && cmp 9qemu.u /n/9fat/9qemu.u && echo CW_W7_A64_KERNEL_COPY_OK; sha1sum -2 256 9qemu.u; sha1sum -2 256 /n/9fat/9qemu.u",
        ]
        required = {
            2: "CW_W7_A64_CROSS_TOOLS_OK",
            3: "CW_W7_A64_SOURCES_OK",
            4: "CW_W7_A64_KERNEL_COMPILED",
            5: "CW_W7_A64_KERNEL_COPY_OK",
        }
        serial = session(image, commands, result_dir, "w7-arm64-builder",
                         950, required)
    finally:
        server.shutdown()
        server.server_close()
    if not re.search(rb"(?m)^" + compressed.encode() +
                     rb"\s+/tmp/w7-a64\.tgz\r?$", serial):
        raise ValueError("original Ryzova ARM64 source archive SHA absent in guest")
    hashes = re.findall(
        rb"(?m)^([0-9a-f]{64})\s+(?:9qemu\.u|/n/9fat/9qemu\.u)\r?$", serial)
    if len(hashes) != 2 or hashes[0] != hashes[1]:
        raise ValueError("ARM64 source-built producer/installed hashes differ")
    expected = hashes[0].decode("ascii")
    exported = result_dir / "9qemu.u"
    n = read_guest_kernel(image, expected, exported)
    boot = native_arm64_boot(exported, result_dir / "w7-arm64-serial.log")
    receipt = {
        "schema": SCHEMA, "source_commit": source_commit,
        "9front_pinned_bootstrap_gzip_sha256": PIN,
        "9front_pinned_bootstrap_raw_sha256": base,
        "ryzova_arm64_original_source_file_count": len(files),
        "ryzova_arm64_source_sha256": {p: files[p] for p in BOOT_FILES},
        "ryzova_arm64_bundle_sha256": compressed,
        "source_built_arm64_9qemu_u_sha256": expected,
        "source_built_arm64_9qemu_u_bytes": n,
        **boot,
        "native_ryzova_arm64_kernel_boot_qualified": True,
        "actual_native_arm64_windows_pe_qualified": False,
        "full_windows_v1_release_qualified": False,
        "real_physical_arm64_hardware_qualified": False,
        "physical_power_cut_qualified": False,
        "general_windows_compatibility": False,
    }
    (result_dir / "w7-arm64-kernel-boot.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")
    print(json.dumps({
        "schema": SCHEMA,
        "source_commit": source_commit,
        "arm64_kernel_sha256": expected,
        "native_ryzova_arm64_kernel_boot_qualified": True,
        "actual_native_arm64_windows_pe_qualified": False,
        "physical_power_cut_qualified": False,
    }, sort_keys=True))
    return receipt


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--bootstrap-gzip", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(a.image, a.bootstrap_gzip, a.output)
