# SPDX-License-Identifier: AGPL-3.0-only
"""Prepare and verify a read-only Compact Windows AMD64 bench run."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from compact_windows_w6_native import ROOT, case_specs, digest, parse_cases, references

SCHEMA = "compact-windows-amd64-bench/v1"
STAGE = "/tmp/cw-hw"
BOOT = "/n/9fat/9pc64"
CASES = ("api", "buffers", "heap", "integer", "divide-zero", "access-fault", "illegal-instruction")
ASSETS = ("9pc64", "compact-windows", *(name + ".exe" for name in CASES))
HOST_FIELDS = ("machine_model", "cpu_model", "firmware_version", "boot_device")


def json_bytes(data):
    return (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()


def valid_hash(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def plan9_script(run_id):
    lines = [
        "#!/bin/rc",
        f"echo CW_HW_BEGIN_{run_id}",
        "cat '#Z/version'",
        "cat '#Z/foundation'",
        "cat '#Z/abi'",
        "echo CW_HW_CPU $objtype",
        f"sha1sum -2 256 {BOOT}",
        f"sha1sum -2 256 {STAGE}/compact-windows",
    ]
    for name in CASES:
        image = f"{STAGE}/{name}.exe"
        lines.extend([
            f"sha1sum -2 256 {image}",
            f"echo CW_CASE_{name}_BEGIN",
            f"{STAGE}/compact-windows {image}",
            f"echo CW_CASE_{name}_END",
        ])
    lines.append(f"echo CW_HW_END_{run_id}")
    return "\n".join(lines) + "\n"


def prepare(fixtures, kernel, runtime, destination):
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    receipt = json.loads((fixtures / "w3.json").read_text(encoding="utf-8-sig"))
    fixture_commit = receipt.get("source_commit")
    if not valid_hash(source, 40) or not valid_hash(fixture_commit, 40):
        raise ValueError("missing source or Windows fixture commit")
    hashes = references(fixtures, fixture_commit)
    files = {"9pc64": kernel, "compact-windows": runtime}
    files.update({name + ".exe": fixtures / (name + ".exe") for name in CASES})
    asset_hashes = {name: digest(path) for name, path in files.items()}
    if any(not path.stat().st_size for path in files.values()):
        raise ValueError("empty kernel, runtime or PE input")
    if any(asset_hashes[name + ".exe"] != hashes[name] for name in CASES):
        raise ValueError("fixture differs from Windows reference receipt")
    manifest = {"schema": SCHEMA, "build_source_commit": source,
                "fixture_source_commit": fixture_commit, "sha256": asset_hashes}
    raw = json_bytes(manifest)
    run_id = hashlib.sha256(raw).hexdigest()[:24]
    destination.mkdir()
    for name, path in files.items():
        shutil.copyfile(path, destination / name)
    (destination / "manifest.json").write_bytes(raw)
    (destination / "bench.rc").write_text(plan9_script(run_id), encoding="ascii")
    return manifest


def verify(bundle, serial, hardware):
    raw = (bundle / "manifest.json").read_bytes()
    manifest = json.loads(raw)
    if (manifest.get("schema") != SCHEMA or
            any(not valid_hash(manifest.get(key), 40) for key in
                ("build_source_commit", "fixture_source_commit"))):
        raise ValueError("invalid bundle manifest")
    hashes = manifest.get("sha256", {})
    if set(hashes) != set(ASSETS):
        raise ValueError("wrong bundle asset set")
    for name in ASSETS:
        if not valid_hash(hashes[name], 64) or digest(bundle / name) != hashes[name]:
            raise ValueError(f"bundle asset hash mismatch: {name}")

    if (hardware.get("operator_observed_bare_metal") is not True or
            hardware.get("operator_booted_kernel_from_bundle") is not True or any(
        not isinstance(hardware.get(field), str) or not hardware[field].strip()
        for field in HOST_FIELDS
    )):
        raise ValueError("missing operator hardware observations")
    if re.search(r"\b(qemu|virtio|vmware|virtualbox|kvm|hyper-v|bochs)\b",
                 " ".join(hardware[field] for field in HOST_FIELDS), re.I):
        raise ValueError("hardware record identifies a virtual platform")

    run_id = hashlib.sha256(raw).hexdigest()[:24]
    start = f"CW_HW_BEGIN_{run_id}"
    end = f"CW_HW_END_{run_id}"
    lines = serial.decode("utf-8", errors="replace").splitlines()
    if lines.count(start) != 1 or lines.count(end) != 1 or lines.index(start) >= lines.index(end):
        raise ValueError("missing or ambiguous bench capture frame")
    frame = lines[lines.index(start)+1:lines.index(end)]
    if not all(frame.count(line) == 1 for line in (
        "Ryzova Kernel 0.1.0-dev", "9front-derived", "experimental-0", "CW_HW_CPU amd64"
    )):
        raise ValueError("missing native AMD64 kernel identity")
    for name, expected in hashes.items():
        path = BOOT if name == "9pc64" else STAGE + "/" + name
        measured = [line.split()[0] for line in frame
                    if re.fullmatch(r"[0-9a-f]{64}\s+" + re.escape(path), line)]
        if measured != [expected]:
            raise ValueError(f"bench capture hash mismatch: {name}")
    for name in CASES:
        if any(frame.count(f"CW_CASE_{name}_{bound}") != 1 for bound in ("BEGIN", "END")):
            raise ValueError(f"missing or ambiguous case frame: {name}")
    specs = case_specs()
    cases = parse_cases(("\n".join(frame) + "\n").encode(), {name: specs[name] for name in CASES})
    return {"schema": SCHEMA, "scope": "operator-observed AMD64 console and CRT bench",
            "build_source_commit": manifest["build_source_commit"],
            "fixture_source_commit": manifest["fixture_source_commit"],
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "serial_sha256": hashlib.sha256(serial).hexdigest(),
            "hardware": {key: hardware[key] for key in HOST_FIELDS},
            "operator_observed_bare_metal": True, "operator_booted_kernel_from_bundle": True,
            "console_capture_validated": True, "storage_power_loss_qualified": False,
            "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("prepare")
    for arg in ("fixtures", "kernel", "runtime", "out"):
        pack.add_argument("--" + arg, required=True, type=Path)
    check = commands.add_parser("verify")
    for arg in ("bundle", "serial", "hardware", "out"):
        check.add_argument("--" + arg, required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.fixtures, args.kernel, args.runtime, args.out)
        else:
            receipt = verify(args.bundle, args.serial.read_bytes(),
                             json.loads(args.hardware.read_bytes()))
            with args.out.open("xb") as file:
                file.write(json_bytes(receipt))
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Bench evidence rejected: {error}\n")


if __name__ == "__main__":
    main()
