# SPDX-License-Identifier: GPL-3.0-only
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


def digest_line(log, path, last=False):
    matches = re.findall(rb"(?m)^([0-9a-f]{64})\s+" + re.escape(path.encode()) + rb"\r?$", log)
    if not matches or (not last and len(matches) != 1):
        raise ValueError(f"expected exactly one digest for {path}")
    return matches[-1].decode()


def main(image, bootstrap, include_m3=False, m4_reference=None, m5_reference=None, m6_reference=None):
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
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    m4_hash = None
    if m4_reference is not None:
        m4_binary = (m4_reference / "m4").read_bytes()
        m4_hash = hashlib.sha256(m4_binary).hexdigest()
        if ((m4_reference / "commit.txt").read_text().strip() != commit or
                (m4_reference / "sha256.txt").read_text().split() != [m4_hash, "evidence/m4"] or
                (m4_reference / "stdout.txt").read_bytes() != b"FLEX_MACOS_M4_DYNAMIC\n" or
                (m4_reference / "stderr.txt").read_bytes() != b"" or
                (m4_reference / "exit.txt").read_text().strip() != "47"):
            raise ValueError("M4 macOS reference evidence mismatch")
        (output / "reference-m4").write_bytes(m4_binary)
    m5_hash = None
    if m5_reference is not None:
        m5_binary = (m5_reference / "m5").read_bytes()
        m5_hash = hashlib.sha256(m5_binary).hexdigest()
        if ((m5_reference / "commit.txt").read_text().strip() != commit or
                (m5_reference / "sha256.txt").read_text().split() != [m5_hash, "evidence/m5"] or
                (m5_reference / "stdout.txt").read_bytes() != b"FLEX_MACOS_M5_ARM64!\n" or
                (m5_reference / "stderr.txt").read_bytes() != b"" or
                (m5_reference / "exit.txt").read_text().strip() != "53"):
            raise ValueError("M5 macOS reference evidence mismatch")
        (output / "reference-m5").write_bytes(m5_binary)
    m6_hashes = {}
    if m6_reference is not None:
        for arch in ("x86_64", "arm64"):
            ref = m6_reference / f"compact-macos-m6-{arch}"
            binary = (ref / "m6").read_bytes()
            digest = hashlib.sha256(binary).hexdigest()
            if ((ref / "commit.txt").read_text().strip() != commit or
                    (ref / "sha256.txt").read_text().split() != [digest, "evidence/m6"] or
                    (ref / "stdout.txt").read_bytes() != b"IN!\n" or
                    (ref / "stderr.txt").read_bytes() or
                    (ref / "exit.txt").read_text().strip() != "61" or
                    (ref / "entry.txt").read_bytes() != b"IN!\nFLEX_NOTE=demo"):
                raise ValueError(f"M6 macOS reference evidence mismatch for {arch}")
            (output / f"m6-{arch}").write_bytes(binary)
            m6_hashes[arch] = digest
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
            if m4_reference is not None:
                commands.extend([
                    "hget http://10.0.2.2:8000/reference-m4 > /tmp/mac-m4; sha1sum -2 256 /tmp/mac-m4",
                    "echo M4_BEGIN; compact-macos-m2 --dynamic /tmp/mac-m4 && echo M4_END",
                ])
            if m5_reference is not None:
                commands.extend([
                    "hget http://10.0.2.2:8000/reference-m5 > /tmp/mac-m5; sha1sum -2 256 /tmp/mac-m5",
                    "echo M5_BEGIN; compact-macos-m2 --arm64 /tmp/mac-m5 && echo M5_END",
                ])
            for arch, mode in (("x86_64", "--files-x86"), ("arm64", "--files-arm64")):
                if arch not in m6_hashes:
                    continue
                root = f"/tmp/m6-{arch}"
                binary = f"/tmp/m6-bin-{arch}"
                commands.extend([
                    f"mkdir -p {root}; echo 'IN!' > {root}/entry.txt",
                    f"hget http://10.0.2.2:8000/m6-{arch} > {binary}; sha1sum -2 256 {binary}",
                ])
                for case, grant, name in (("ok", root, "entry.txt"),
                                          ("escape", root, "../mac-outside"),
                                          ("nogrant", "-", "entry.txt")):
                    marker = f"M6_{arch}_{case}"
                    commands.append(f"echo {marker}; compact-macos-m2 {mode} {binary} {grant} {name} demo && echo {marker}_END")
                commands.append(f"sha1sum -2 256 {root}/entry.txt")
            if m6_hashes:
                commands.append("sha1sum -2 256 /tmp/mac-outside")
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
        "source_commit": commit,
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
        if digest_line(run, "/tmp/mac-outside", last=bool(m6_hashes)) != hashlib.sha256(b"SAFE\n").hexdigest():
            raise ValueError("M3 outside file changed")
        report["m3"] = {"fixture_sha256": M3_SHA, "allowed_exit": 37, "denied_exit": 13,
                        "missing_grant_exit": 13, "stdout": "IN!\n",
                        "granted_bytes": content.decode(), "outside_unchanged": True}
    if m4_reference is not None:
        if digest_line(run, "/tmp/mac-m4") != m4_hash:
            raise ValueError("guest M4 executable digest mismatch")
        m4 = re.search(rb"(?m)^M4_BEGIN\r?\nFLEX_MACOS_M4_DYNAMIC\r?\n"
                       rb"MAC_M4_EXIT 47 STEPS ([0-9]+) WRITE_CALLS 1 REBASES 1"
                       rb"\r?\nM4_END\r?$", run)
        if not m4 or not 1 <= int(m4[1]) <= 64:
            raise ValueError("M4 output, exit or relocation evidence mismatch")
        report["m4"] = {"reference_sha256": m4_hash, "stdout": "FLEX_MACOS_M4_DYNAMIC\n",
                        "guest_exit": 47, "instruction_steps": int(m4[1]),
                        "write_calls": 1, "rebases": 1}
    if m5_reference is not None:
        if digest_line(run, "/tmp/mac-m5") != m5_hash:
            raise ValueError("guest M5 executable digest mismatch")
        m5 = re.search(rb"(?m)^M5_BEGIN\r?\nFLEX_MACOS_M5_ARM64!\r?\n"
                       rb"MAC_M5_EXIT 53 STEPS ([0-9]+) WRITE_CALLS 1 REBASES 1"
                       rb"\r?\nM5_END\r?$", run)
        if not m5 or not 1 <= int(m5[1]) <= 64:
            raise ValueError("M5 output, exit or relocation evidence mismatch")
        report["m5"] = {"reference_sha256": m5_hash, "stdout": "FLEX_MACOS_M5_ARM64!\n",
                        "guest_exit": 53, "instruction_steps": int(m5[1]),
                        "write_calls": 1, "rebases": 1,
                        "guest_architecture": "arm64", "flex_host_architecture": "amd64"}
    if m6_hashes:
        report["m6"] = {}
        for arch, digest in m6_hashes.items():
            if digest_line(run, f"/tmp/m6-bin-{arch}") != digest:
                raise ValueError(f"M6 executable hash mismatch for {arch}")
            for case in ("ok", "escape", "nogrant"):
                marker = f"M6_{arch}_{case}".encode()
                prefix = (rb"IN!\r?\nMAC_M6_EXIT 61" if case == "ok" else rb"MAC_M6_EXIT 13")
                stats = (b"OPEN 1 READ 1 WRITE 1 CLOSE 1 DENIED 0" if case == "ok" else
                         b"OPEN 0 READ 0 WRITE 0 CLOSE 0 DENIED 1")
                match = re.search(rb"(?m)^" + marker + rb"\r?\n" + prefix +
                                  rb" STEPS ([0-9]+) " + stats + rb"\r?\n" + marker + rb"_END\r?$", run)
                if not match or not 1 <= int(match[1]) <= 64:
                    raise ValueError(f"M6 receipt mismatch for {arch} {case}: " + run[-4500:].decode(errors="replace"))
            if digest_line(run, f"/tmp/m6-{arch}/entry.txt") != hashlib.sha256(b"IN!\nFLEX_NOTE=demo").hexdigest():
                raise ValueError(f"M6 file bytes mismatch for {arch}")
            report["m6"][arch] = {"reference_sha256": digest, "stdout": "IN!\n", "guest_exit": 61,
                                  "file_bytes": "IN!\nFLEX_NOTE=demo", "escape_exit": 13,
                                  "missing_grant_exit": 13, "outside_unchanged": True}
    (output / "qualification.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), "--m3" in sys.argv[3:],
         Path(sys.argv[4]) if len(sys.argv) >= 5 and sys.argv[3] == "--m3" else None,
         Path(sys.argv[5]) if len(sys.argv) >= 6 and sys.argv[3] == "--m3" else None,
         Path(sys.argv[6]) if len(sys.argv) == 7 and sys.argv[3] == "--m3" else None)
