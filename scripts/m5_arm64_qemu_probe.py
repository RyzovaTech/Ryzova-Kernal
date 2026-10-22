#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Attempt a fresh QEMU virt boot of source-built ARM64 kernel from 9fat.

Only runs when the 9front guest has actually linked and installed 9qemu.u.
Copies no unreviewed proprietary binaries and uploads no bootable binaries.
"""
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
CROSS = OUT / "m5-arm64-native-build.json"


def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda:f.read(1024*1024),b""):
            h.update(data)
    return h.hexdigest()


def find_fat(raw):
    with raw.open("rb") as f:
        for off in range(0,128*1024*1024,512):
            f.seek(off)
            b=f.read(512)
            if len(b)<512:
                break
            if (b[:1] in (b"\xeb",b"\xe9") and
                b[510:512]==b"\x55\xaa" and
                (b[54:62].startswith(b"FAT") or b[82:90].startswith(b"FAT"))):
                yield off


def probe(overlay):
    cross=json.loads(CROSS.read_text(encoding="utf-8"))
    source=cross.get("source_sha","")
    report={
        "schema":"ryzova-m5-arm64-native-qemu/v1",
        "source_sha":source,
        "arm64_kernel_link":cross.get("arm64_kernel_link"),
        "arm64_qemu_boot_observed":False,
        "arm64_userland_function_verified":False,
        "arm64_virtio_network_verified":False,
        "arm64_virtio_storage_verified":False,
        "newly_certified_physical_models":0,
        "release_status":"blocked",
    }
    if cross.get("arm64_kernel_link")!="pass":
        report["outcome"]="not-booted-native-link-incomplete"
        return report
    guest_text=SERIAL.read_text(encoding="utf-8",errors="replace")
    if not re.search(r"(?:^|\r?\n)M5_ARM64_COPY_STATUS_\s*(?:\r?\n)", guest_text):
        raise RuntimeError("ARM64 link passed but guest uImage FAT copy not attested")
    hashes=re.findall(r"(?m)^([0-9a-f]{64})\s+9qemu\.u\s*$",guest_text)
    if not hashes:
        raise RuntimeError("ARM64 link passed without native guest uImage SHA256")
    expected=hashes[-1]
    with tempfile.TemporaryDirectory(prefix="ryzova-m5-") as td:
        td=Path(td)
        raw=td/"disk.raw"
        kernel=td/"9qemu.u"
        subprocess.run(["qemu-img","convert","-O","raw","-S","4k",
                        str(overlay),str(raw)],check=True,stdout=subprocess.DEVNULL)
        found=False
        for off in find_fat(raw):
            p=subprocess.run(["mcopy","-o","-i",str(raw)+"@@"+str(off),
                              "::9qemu.u",str(kernel)],capture_output=True,text=True)
            if p.returncode==0 and kernel.is_file() and kernel.stat().st_size>100_000:
                found=True
                break
        if not found:
            raise RuntimeError("Unable to extract guest-built ARM64 uImage")
        digest=sha256(kernel)
        if digest!=expected:
            raise RuntimeError("M5 guest/host SHA256 mismatch for ARM64 uImage")
        report["independent_kernel_sha256_verified"]=True
        report["source_built_kernel_sha256"]=digest
        cmd=["qemu-system-aarch64","-machine","virt,highmem=off,gic-version=2",
             "-cpu","cortex-a57","-smp","2","-m","2048",
             "-display","none","-nographic","-monitor","none",
             "-kernel",str(kernel),"-no-reboot"]
        try:
            result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                  timeout=75,check=False)
            output=result.stdout
        except subprocess.TimeoutExpired as exc:
            output=exc.stdout or b""
        (OUT/"m5-arm64-boot-serial.log").write_bytes(output)
        # A kernel banner and CPU0 print coming from QEMU, not a unit test echo,
        # make a boot OBSERVATION, not an operational hardware certification.
        banner=bool(re.search(rb"(?:^|\r?\n)Plan 9(?:\r?\n)",output))
        cpu=bool(re.search(rb"(?:^|\r?\n)cpu0:[^\r\n]{1,160}(?:\r?\n)",output))
        report["arm64_qemu_boot_observed"]=banner and cpu
        report["outcome"]="kernel-boot-observed" if banner and cpu else "kernel-boot-unconfirmed"
    return report


def main():
    if len(sys.argv)!=2:
        sys.exit("usage: m5_arm64_qemu_probe.py <native-9front-qcow2-overlay>")
    OUT.mkdir(parents=True,exist_ok=True)
    report=probe(Path(sys.argv[1]).resolve())
    (OUT/"m5-arm64-qemu-probe.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))
    if report.get("arm64_kernel_link")=="pass" and not report["arm64_qemu_boot_observed"]:
        print("M5 ARM64 QEMU boot remains UNCONFIRMED",file=sys.stderr)
    # M5 source CI is allowed to finish, but M6 functional release remains blocked.
    return 0


if __name__=="__main__":
    raise SystemExit(main())
