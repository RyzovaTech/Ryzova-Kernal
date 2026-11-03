# SPDX-License-Identifier: AGPL-3.0-only
"""W8 native Windows-app gate: exact MSVC PE, source, stdin, output and calls.

A hosted Windows PE reference is never native Ryzova/QEMU evidence.
A fabricated JSON flag without the original QEMU serial logs fails closed.
This gate qualifies only one pinned MIT source-available ASCII wc profile.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from compact_windows_w6_native import w8_reference, parse_cases, ROOT

SCHEMA = "compact-windows-w8-native-app-acceptance/v1"
INPUT = b"alpha beta\nsecond\n"
EXPECTED = b"2 3 18\n"


def sha256(value):
    if isinstance(value,Path):value=value.read_bytes()
    if type(value) is not bytes:raise ValueError("digest input not bytes")
    return hashlib.sha256(value).hexdigest()


def accept(native, windows, pe, fresh_log, source_commit):
    if not isinstance(native,dict) or native.get("schema")!="compact-windows-w6-native/v1":
        raise ValueError("missing original W6 source-built QEMU evidence")
    if not isinstance(source_commit,str) or re.fullmatch(r"[0-9a-f]{40}",source_commit) is None:
        raise ValueError("missing exact-head native source")
    if native.get("source_commit")!=source_commit or native.get("native_amd64_qemu_qualified") is not True:
        raise ValueError("W6 kernel source identity unqualified")
    if not isinstance(windows,dict) or windows.get("schema")!="compact-windows-w8-sbase-wc-host/v1":
        raise ValueError("Windows-host reference invalid")
    if windows.get("source_commit")!=source_commit or windows.get("windows_reference_qualified") is not True:
        raise ValueError("Windows-host reference does not correspond to this source head")
    witness=windows.get("no_crt_candidate")
    if not isinstance(witness,dict) or witness.get("windows_reference_default_passed") is not True:
        raise ValueError("missing Windows-host real PE execution")
    if (witness.get("candidate_structurally_eligible_for_native_investigation") is not True
        or witness.get("direct_imports")!=5
        or witness.get("missing_or_ordinal_imports")!=[]
        or witness.get("native_guest_execution_qualified") is not False):
        raise ValueError("original fixed Win32 PE import profile not verified")
    binary=Path(pe)
    if not binary.is_file() or binary.stat().st_size>4*1024*1024:
        raise ValueError("missing/beyond-limit transferred Microsoft-compiled MIT source PE")
    binary_sha=sha256(binary)
    if witness.get("source_binary_sha256")!=binary_sha:
        raise ValueError("PE changed after successful Windows reference execution")
    w8=native.get("w8_source_available_app")
    if not isinstance(w8,dict) or w8.get("schema")!="compact-windows-w8-native/v1":
        raise ValueError("no real W8 QEMU case in W6 source-built report")
    for k,v in (
        ("source_commit",source_commit),
        ("windows_reference_pe_sha256",binary_sha),
        ("guest_pe_sha256",binary_sha),
        ("stdin_sha256",sha256(INPUT)),
        ("expected_stdout_sha256",sha256(EXPECTED)),
        ("native_qemu_same_windows_pe_verified",True),
        ("native_qemu_stdin_stdout_exit_verified",True),
        ("transitive_windows_runtime_qualified",False),
        ("windows_v1_release_qualified",False),
        ("physical_hardware_qualified",False),
        ("general_windows_compatibility",False),
    ):
        if w8.get(k)!=v:raise ValueError("invalid W8 exact native claim: "+k)
    if type(fresh_log) is not bytes or b"Ryzova Kernel 0.1.0-dev" not in fresh_log:
        raise ValueError("no original source-built QEMU identity")
    log=fresh_log
    for name,digest in (
        ("/tmp/cw-w8wc.exe",binary_sha),
        ("/tmp/cw-w8-input",sha256(INPUT)),
    ):
        if not re.search(rb"(?m)^"+digest.encode()+rb"\s+"+re.escape(name.encode())+rb"\r?$",log):
            raise ValueError("native Ryzova guest PE/input hashes absent: "+name)
    spec={"w8wc":{"image":"w8wc","status":0,"code":0,
                  "out":EXPECTED.hex(),"err":"","args":"-I /tmp/cw-w8-input"}}
    actual=parse_cases(log,spec)["w8wc"]
    if actual!=w8.get("native_qemu_case"):
        raise ValueError("QEMU serial and W8 JSON disagree")
    for api in ("ReadFile","WriteFile","GetStdHandle","ExitProcess"):
        if actual.get("calls",{}).get(api,0)<1:
            raise ValueError("missing original Win32 user ABI call: "+api)
    return {
        "schema":SCHEMA,
        "source_commit":source_commit,
        "windows_host_compiled_pe_sha256":binary_sha,
        "native_guest_exact_pe_sha256":binary_sha,
        "native_guest_stdin_sha256":sha256(INPUT),
        "native_guest_stdout_sha256":sha256(EXPECTED),
        "source_built_amd64_kernel_qemu_verified":True,
        "genuine_mit_sbase_wc_ascii_profile_qualified":True,
        "native_cases":1,
        "existing_w6_22_case_gate_unchanged":True,
        "full_windows_v1_release_qualified":False,
        "physical_hardware_qualified":False,
        "arm64_windows_qualified":False,
        "general_windows_compatibility":False,
        "merge_authorized":False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence",type=Path)
    parser.add_argument("--windows-reference",type=Path,required=True)
    parser.add_argument("--pe",type=Path,required=True)
    parser.add_argument("--source-sha",required=True)
    args=parser.parse_args()
    result=accept(
        json.loads((args.evidence/"qualification.json").read_text()),
        json.loads(args.windows_reference.read_text(encoding="utf-8-sig")),
        args.pe,(args.evidence/"fresh-serial.log").read_bytes(),args.source_sha)
    (args.evidence/"w8-application-acceptance.json").write_text(
        json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=="__main__":main()
