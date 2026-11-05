# SPDX-License-Identifier: AGPL-3.0-only
"""Build and execute the pinned M1 program in a source-built Flex QEMU guest."""
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import threading

# Reuse QEMU evidence transport only. The Mac runtime has no Windows code dependency.
from compact_windows_w6_native import bootstrap_provenance, extract_kernel, session

from compact_macos_m3_fixture import build as build_m3

M3_SHA = "4b2fdd6c3fbe8c4c9841f6be0b3b972e1d73c1aca341fa1fea9f4716f90bf490"

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = "478499eefd5228f56ffaed4dafc07436b01ae1319f1cc95998aecb92e46afc1f"
OUTPUT = b"FLEX_MACOS_M1_REFERENCE"


def digest_line(log, path):
    matches = re.findall(rb"(?m)^([0-9a-f]{64})\s+" + re.escape(path.encode()) + rb"\r?$", log)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one digest for {path}")
    return matches[0].decode()


def main(image, bootstrap, include_m3=False):
    base_sha = bootstrap_provenance(image, bootstrap)
    output = ROOT / "artifacts/compact-macos-m2"
    output.mkdir(parents=True, exist_ok=True)
    fixture = (ROOT / "tests/fixtures/macos_m1_reference.macho").read_bytes()
    if hashlib.sha256(fixture).hexdigest() != REFERENCE:
        raise ValueError("M1 fixture provenance mismatch")
    (output / "reference").write_bytes(fixture)
    if include_m3:
        fixture_m3 = build_m3()
        if hashlib.sha256(fixture_m3).hexdigest() != M3_SHA:
            raise ValueError("M3 fixture provenance mismatch")
        (output / "reference-m3").write_bytes(fixture_m3)
    source = subprocess.check_output(["git", "ls-files", "sys/src/9", "sys/include",
                                      "amd64/include", "ryzova/compat/macos"], cwd=ROOT, text=True)
    archive = output / "source.tgz"
    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for filename in source.splitlines():
            target = filename.replace("ryzova/compat/macos", "sys/src/cmd/compact-macos-m2", 1)
            tar.add(ROOT / filename, arcname=target, recursive=False)
    source_sha = hashlib.sha256(archive.read_bytes()).hexdigest()

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(output))
    with ThreadingHTTPServer(("127.0.0.1", 8000), handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            setup = "ip/ipconfig -d ether /net/ether0; webfs"
            build = session(image, [
                setup,
                "hget http://10.0.2.2:8000/source.tgz > /tmp/mac-source.tgz; sha1sum -2 256 /tmp/mac-source.tgz",
                "cd /; tar xzf /tmp/mac-source.tgz",
                "cd /sys/src/cmd/compact-macos-m2; mk install > /tmp/mac-build.log >[2=1] && echo MAC_NATIVE_OK; cat /tmp/mac-build.log",
                "cd /sys/src/9/pc64; mk > /tmp/mac-kernel.log >[2=1] && echo MAC_KERNEL_OK; tail -n 25 /tmp/mac-kernel.log",
                "9fs 9fat; cd /sys/src/9/pc64; cp 9pc64 /n/9fat/9pc64 && cmp 9pc64 /n/9fat/9pc64 && echo MAC_COPY_OK; sha1sum -2 256 9pc64",
                "sha1sum -2 256 /amd64/bin/compact-macos-m2; echo sync >> /srv/hjfs.cmd; sleep 3",
            ], output, "build", 850, {3:"MAC_NATIVE_OK", 4:"MAC_KERNEL_OK", 5:"MAC_COPY_OK"})
            if digest_line(build, "/tmp/mac-source.tgz") != source_sha:
                raise ValueError("guest source archive mismatch")
            kernel_sha = digest_line(build, "9pc64")
            extract_kernel(image, output, kernel_sha)
            runner_sha = digest_line(build, "/amd64/bin/compact-macos-m2")
            commands = [
                "cat '#Z/version'; sha1sum -2 256 /amd64/bin/compact-macos-m2",
                setup,
                "hget http://10.0.2.2:8000/reference > /tmp/mac-reference; sha1sum -2 256 /tmp/mac-reference",
                "echo MAC_M2_BEGIN; /amd64/bin/compact-macos-m2 /tmp/mac-reference && echo MAC_M2_END",
            ]
            if include_m3:
                commands.extend([
                    "mkdir -p /tmp/mac-grant; echo 'IN!' > /tmp/mac-grant/entry.txt; echo SAFE > /tmp/mac-outside",
                    "hget http://10.0.2.2:8000/reference-m3 > /tmp/mac-m3; sha1sum -2 256 /tmp/mac-m3",
                    "echo M3_ALLOWED; compact-macos-m2 /tmp/mac-m3 /tmp/mac-grant entry.txt demo && echo M3_ALLOWED_END",
                    "echo M3_DENIED; compact-macos-m2 /tmp/mac-m3 /tmp/mac-grant ../mac-outside demo && echo M3_DENIED_END",
                    "echo M3_NO_GRANT; compact-macos-m2 /tmp/mac-m3 - entry.txt demo && echo M3_NO_GRANT_END",
                    "sha1sum -2 256 /tmp/mac-grant/entry.txt /tmp/mac-outside",
                ])
            run = session(image, commands, output, "fresh", 120, {3:"MAC_M2_END"})
        finally:
            server.shutdown()
    if b"Ryzova Kernel" not in run or digest_line(run, "/amd64/bin/compact-macos-m2") != runner_sha:
        raise ValueError("fresh kernel or native runner identity mismatch")
    if digest_line(run, "/tmp/mac-reference") != REFERENCE:
        raise ValueError("guest Mach-O digest mismatch")
    receipt = re.search(rb"(?m)^MAC_M2_BEGIN\r?\n" + OUTPUT +
                        rb"\r?\nMAC_M2_EXIT 37 STEPS ([0-9]+) WRITE_CALLS 1\r?\nMAC_M2_END\r?$", run)
    if not receipt or not 1 <= int(receipt[1]) <= 64:
        raise ValueError("native output, exit or bounded execution mismatch")
    report = {
        "reference_sha256": REFERENCE,
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_archive_sha256": source_sha,
        "bootstrap_sha256": base_sha,
        "kernel_sha256": kernel_sha,
        "runner_sha256": runner_sha,
        "stdout": OUTPUT.decode()+"\n",
        "guest_exit": 37,
        "instruction_steps": int(receipt[1]),
        "write_calls": 1,
    }
    if include_m3:
        if digest_line(run, "/tmp/mac-m3") != M3_SHA:
            raise ValueError("guest M3 fixture digest mismatch")
        cases = (
            (b"M3_ALLOWED", b"IN!\r?\n", b"37", b"OPEN 1 READ 1 WRITE 1 DENIED 0"),
            (b"M3_DENIED", b"", b"13", b"OPEN 0 READ 0 WRITE 0 DENIED 1"),
            (b"M3_NO_GRANT", b"", b"13", b"OPEN 0 READ 0 WRITE 0 DENIED 1"),
        )
        for marker, stdout, status, counts in cases:
            match = re.search(rb"(?m)^" + marker + rb"\r?\n" + stdout +
                              rb"MAC_M3_EXIT " + status + rb" STEPS ([0-9]+) " +
                              counts + rb"\r?\n" + marker + rb"_END\r?$", run)
            if not match or not 1 <= int(match[1]) <= 64:
                raise ValueError(f"M3 execution receipt mismatch for {marker.decode()}")
        content = b"IN!\nFLEX_NOTE=demo"
        if digest_line(run, "/tmp/mac-grant/entry.txt") != hashlib.sha256(content).hexdigest():
            raise ValueError("M3 granted write bytes mismatch")
        if digest_line(run, "/tmp/mac-outside") != hashlib.sha256(b"SAFE\n").hexdigest():
            raise ValueError("M3 outside file changed")
        report["m3"] = {"fixture_sha256": M3_SHA, "allowed_exit": 37, "denied_exit": 13,
                        "missing_grant_exit": 13, "stdout": "IN!\n",
                        "granted_bytes": content.decode(), "outside_unchanged": True}
    (output / "qualification.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), "--m3" in sys.argv[3:])
