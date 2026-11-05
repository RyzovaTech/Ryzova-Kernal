# SPDX-License-Identifier: AGPL-3.0-only
"""W7: compare exact REAL Windows ARM64-host PE against TWO Linux interpreters.

Windows-native source-built PE must be byte-identical in all three receipts.
One Linux interpreter is AMD64 and one is a real ELF64 AArch64 process under
QEMU userspace. Native Ryzova ARM64 kernel/physical-board remain UNQUALIFIED.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from compact_windows_w7_arm64_qemu_user import (
    ROOT,SRC,MAIN,ENGINE,FIXTURES,sha256,require,command,invoke,
    pe_entry_raw,arm64_linux_elf,mutate
)

SCHEMA = "compact-windows-w7-real-windows-arm64-host-triplet/v1"
HOST_SCHEMA = "compact-windows-w7-native-windows-arm64-host/v1"
CASES = {name+"-"+opt:source for name,source in FIXTURES
         for opt in ("O0","O2")}
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def verify_windows_host_artifact(path,source_sha):
    path=Path(path)
    if (type(source_sha) is not str or
            re.fullmatch(r"[0-9a-f]{40}",source_sha) is None):
        raise ValueError("exact 40-hex PR HEAD commit required")
    manifest=path/"windows-arm64-reference.json"
    if not manifest.is_file() or manifest.is_symlink() or manifest.stat().st_size>40000:
        raise ValueError("missing bounded Windows ARM64 original-source receipt")
    info=json.loads(manifest.read_text(encoding="utf-8-sig"))
    if (info.get("schema")!=HOST_SCHEMA or
            info.get("source_commit")!=source_sha or
            info.get("windows_os_architecture")!="Arm64" or
            info.get("actual_windows_arm64_host_reference_qualified") is not True or
            info.get("native_ryzova_arm64_kernel_boot_qualified") is not False or
            info.get("windows_v1_release_qualified") is not False or
            info.get("physical_arm64_hardware_qualified") is not False or
            not isinstance(info.get("windows_os_version"),str)):
        raise ValueError("Windows ARM64 native host source/qualification scope mismatch")
    cases=info.get("cases")
    if not isinstance(cases,dict) or set(cases)!=set(CASES):
        raise ValueError("Windows ARM64 native host must execute four exact workloads")
    binaries={}
    seen=set()
    for name,source in CASES.items():
        r=cases[name]
        binary=path/(name+".exe")
        if (not isinstance(r,dict) or not binary.is_file() or binary.is_symlink() or
                not 256<=binary.stat().st_size<=4*1024*1024):
            raise ValueError("missing genuine Windows ARM64 compiled PE: "+name)
        image=binary.read_bytes()
        if (r.get("source_sha256")!=sha256(source.read_bytes()) or
                r.get("windows_arm64_pe_sha256")!=sha256(image) or
                r.get("windows_arm64_pe_bytes")!=len(image) or
                r.get("actual_windows_arm64_exit")!=37 or
                r.get("actual_windows_arm64_stdout_sha256")!=EMPTY_SHA or
                r.get("actual_windows_arm64_stderr_sha256")!=EMPTY_SHA or
                r.get("actual_windows_arm64_native_host_passed") is not True):
            raise ValueError("Windows ARM64 host/source/image receipt mismatch: "+name)
        pe_entry_raw(image)
        pe=int.from_bytes(image[0x3c:0x40],"little")
        opt=pe+24
        if (int.from_bytes(image[opt+108:opt+112],"little")<2 or
                int.from_bytes(image[opt+120:opt+124],"little") or
                int.from_bytes(image[opt+124:opt+128],"little")):
            raise ValueError("genuine Windows ARM64 PE unexpectedly imports DLLs")
        if sha256(image) in seen:
            raise ValueError("native Windows ARM64 reference incorrectly reused a PE")
        seen.add(sha256(image))
        binaries[name]=binary
    return info,binaries


def qualify(path,output,source_sha):
    manifest,binaries=verify_windows_host_artifact(path,source_sha)
    root=ROOT
    current=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,
                                    text=True,timeout=15).strip()
    if current!=source_sha:
        raise ValueError("checked-out W7 source differs from Windows ARM64 compiler source")
    hostcc=require("cc")
    armcc=require("aarch64-linux-gnu-gcc")
    emulator=require("qemu-aarch64")
    with tempfile.TemporaryDirectory(prefix="cw-w7-windows-arm64-triplet-") as temp:
        p=Path(temp)
        host=p/"cw-amd64"
        linuxarm=p/"cw-linux-aarch64"
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror"]
        command([hostcc,*flags,ENGINE,MAIN,"-o",host])
        command([armcc,*flags,"-static","-fno-pie","-no-pie",ENGINE,MAIN,"-o",linuxarm])
        arm_sha=arm64_linux_elf(linuxarm.read_bytes())
        host_raw=host.read_bytes()
        if (host_raw[:6]!=b"\x7fELF\x02\x01" or
                int.from_bytes(host_raw[18:20],"little")!=62):
            raise ValueError("Linux host VM must be AMD64 ELF64")
        engines={"linux-amd64":[host],"qemu-linux-aarch64":[emulator,linuxarm]}
        compared={}
        for name,binary in sorted(binaries.items()):
            receipts={label:invoke(cmd,binary) for label,cmd in engines.items()}
            if (receipts["linux-amd64"]!=receipts["qemu-linux-aarch64"] or
                    receipts["linux-amd64"]["status"]!=0 or
                    receipts["linux-amd64"]["exit_code"]!=
                    manifest["cases"][name]["actual_windows_arm64_exit"]):
                raise ValueError("native Windows vs interpreter ISA/PE mismatch: "+name)
            compared[name]={
                "windows_native_arm64_host_exit":37,
                "original_windows_arm64_pe_sha256":sha256(binary.read_bytes()),
                "linux_amd64_interpreter":receipts["linux-amd64"],
                "qemu_aarch64_interpreter":receipts["qemu-linux-aarch64"],
                "same_original_windows_pe_and_exit_qualified":True,
            }
        negatives={}
        original=binaries["integer-O2"].read_bytes()
        for kind,want in (("arm64ec-denied",1),("svc-denied",2),
                          ("illegal-denied",2),("step-limit",4),
                          ("imports-denied",1)):
            data=mutate(original,kind)
            neg=p/(kind+".exe")
            neg.write_bytes(data)
            measurements={n:invoke(cmd,neg) for n,cmd in engines.items()}
            if (measurements["linux-amd64"]!=measurements["qemu-linux-aarch64"] or
                    measurements["linux-amd64"]["status"]!=want):
                raise ValueError("triplet ARM64 modified-PE denial mismatch: "+kind)
            if kind=="step-limit" and measurements["linux-amd64"]["steps"]!=4096:
                raise ValueError("ARM64 guest instruction budget not enforced")
            negatives[kind]={
                "derived_from_genuine_windows_pe_sha256":sha256(original),
                "mutated_pe_sha256":sha256(data),
                "expected_status":want,
                "linux_arm64_qemu_matches_amd64_vm":True,
            }
        result={
            "schema":SCHEMA,
            "source_commit":source_sha,
            "native_windows_arm64_source_receipt_sha256":sha256(
                (Path(path)/"windows-arm64-reference.json").read_bytes()),
            "amd64_linux_interpreter_sha256":sha256(host_raw),
            "aarch64_linux_interpreter_sha256":arm_sha,
            "same_pe_native_windows_arm64_vs_two_linux_interpreters":True,
            "exact_windows_arm64_pe_cases":compared,
            "original_windows_pe_negative_cases":negatives,
            "actual_windows_arm64_host_reference_qualified":True,
            "qemu_linux_arm64_userspace_interpreter_qualified":True,
            "native_ryzova_arm64_kernel_boot_qualified":False,
            "general_windows_arm64_apps_qualified":False,
            "windows_v1_release_qualified":False,
            "physical_arm64_hardware_qualified":False,
        }
        if len(compared)!=4 or len(negatives)!=5:
            raise ValueError("incomplete genuine Windows ARM64-host matrix")
        output=Path(output)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({
            "schema":SCHEMA,"windows_arm64_native_host_cases":len(compared),
            "qemu_arm64_negative_cases":len(negatives),
            "same_pe_native_windows_arm64_vs_two_linux_interpreters":True,
            "native_ryzova_arm64_kernel_boot_qualified":False,
        },sort_keys=True))
        return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-host-dir",type=Path,required=True)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--output",type=Path,required=True)
    opts=parser.parse_args()
    qualify(opts.windows_host_dir,opts.output,opts.source_sha)
