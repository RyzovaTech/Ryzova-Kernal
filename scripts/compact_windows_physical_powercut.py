# SPDX-License-Identifier: AGPL-3.0-only
"""Independent external hardware power-cut evidence candidate validator.

This tool does not power off hardware, claim observed physical effects, or
certify hardware by accepting self-reported JSON. A witness-signed report
is only an immutable candidate for independent human/hardware review.
Its trusted Ed25519 public-key fingerprint MUST be supplied out-of-band,
not copied from the manifest under test.
"""
import argparse
import base64
from datetime import datetime
import hashlib
import os
import stat
import json
from pathlib import Path
import re
import subprocess
import tempfile

SCHEMA="compact-windows-external-powercut/v1"
HEX40=re.compile(r"[0-9a-f]{40}\Z")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
NONCE=re.compile(r"[0-9a-f]{16,64}\Z")


def require_hex(value,pattern,field):
    if not isinstance(value,str) or not pattern.fullmatch(value):
        raise ValueError("invalid "+field)
    return value


def utc(value,field):
    if not isinstance(value,str) or not value.endswith("Z"):
        raise ValueError("UTC timestamp needed for "+field)
    try:
        parsed=datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc:
        raise ValueError("invalid timestamp: "+field) from exc
    return parsed


def audit_report(report):
    if not isinstance(report,dict) or report.get("schema")!=SCHEMA:
        raise ValueError("unknown physical test evidence schema")
    require_hex(report.get("source_commit"),HEX40,"source commit")
    if report.get("architecture")!="amd64" or report.get("target")!="Ryzova Kernel":
        raise ValueError("unsupported physical architecture/target")
    d=report.get("device")
    if not isinstance(d,dict):
        raise ValueError("device inventory missing")
    for key in ("controller_model","controller_firmware","storage_model",
                "storage_firmware","power_cut_fixture_id"):
        v=d.get(key)
        if not isinstance(v,str) or not 2<=len(v)<=128 or any(ord(x)<32 for x in v):
            raise ValueError("missing identified hardware: "+key)
    require_hex(d.get("serial_sha256"),HEX64,"hashed serial")
    if d.get("sector_bytes") not in (512,4096):
        raise ValueError("unsupported physical sector size")
    if d.get("physical_cut_method")!="external-power-controller":
        raise ValueError("software SIGKILL/QEMU reset is NOT physical power loss")

    cycles=report.get("power_cycles")
    if not isinstance(cycles,list) or not 3<=len(cycles)<=100:
        raise ValueError("at least three independent physical cycles required")
    nonces=set()
    counters=set()
    ids=set()
    last_counter=-1
    for c in cycles:
        if not isinstance(c,dict):
            raise ValueError("missing physical power cycle")
        name=c.get("cycle_id")
        if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}",name) or name in ids:
            raise ValueError("duplicated or invalid physical cycle")
        ids.add(name)
        nonce=require_hex(c.get("flush_ack_nonce"),NONCE,"flush ACK nonce")
        if nonce in nonces:
            raise ValueError("reused flush nonce")
        nonces.add(nonce)
        expected=require_hex(c.get("acknowledged_file_sha256"),HEX64,"ACK file hash")
        recovered=require_hex(c.get("post_reboot_file_sha256"),HEX64,"physical recovery")
        if expected!=recovered:
            raise ValueError("acknowledged bytes not recovered after power interruption")
        for key in ("flush_ack_serial_log_sha256","witness_cut_log_sha256",
                    "post_reboot_serial_log_sha256"):
            require_hex(c.get(key),HEX64,key)
        if c.get("flush_acked") is not True or c.get("cut_by_independent_controller") is not True:
            raise ValueError("acknowledged external power interruption not observed")
        if c.get("cache_flush_command") not in (
            "SCSI_SYNCHRONIZE_CACHE_10","SCSI_SYNCHRONIZE_CACHE_16","NVME_FLUSH"):
            raise ValueError("cache flush primitive and controller audit missing")
        counter=c.get("independent_controller_event_counter")
        if type(counter) is not int or counter<=last_counter or counter in counters:
            raise ValueError("stale or replayed independent power controller event")
        last_counter=counter;counters.add(counter)
        t_ack=utc(c.get("ack_utc"),"ack UTC")
        t_cut=utc(c.get("power_cut_utc"),"independent power-cut UTC")
        t_restore=utc(c.get("power_restored_utc"),"restore UTC")
        if not t_ack<t_cut<t_restore or (t_cut-t_ack).total_seconds()>120 or (
            t_restore-t_cut).total_seconds()>3600:
            raise ValueError("invalid flush / power-cut / restart sequence")
        if c.get("power_absent_measured") is not True:
            raise ValueError("external power absence not witnessed")
    for negative_name in ("flush-fault","flush-sticky"):
        negative=(report.get("negative_cases") or {}).get(negative_name)
        if not isinstance(negative,dict) or negative.get("win32_error")!=1117 or (
            negative.get("successful_flush_acks")!=0):
            raise ValueError("physical storage failure was incorrectly acknowledged")
        require_hex(negative.get("independent_event_log_sha256"),HEX64,negative_name)
    if report.get("full_windows_compatibility") is not False or (
        report.get("arm64_windows_qualified") is not False):
        raise ValueError("unrelated Windows/ARM64 claim cannot be promoted")
    return {
        "schema":"compact-windows-powercut-review/v1",
        "source_commit":report["source_commit"],
        "device_serial_sha256":d["serial_sha256"],
        "signed_external_cycles":len(cycles),
        "distinct_controller_events":len(counters),
        "all_acknowledged_file_digests_matched":True,
        "fault_and_sticky_ack_denials":True,
        "witness_signature_verified":False,
        "ready_for_independent_hardware_review":False,
        "physical_hardware_qualified":False,
        "general_windows_compatibility":False,
        "scope":"Evidence-format integrity only until independent witness signature and destructive physical test reviewed",
    }


# Never trust hash-looking manifest strings without their original
# external witness/serial logs. All paths are fixed names below, and only
# regular, nonempty, bounded files opened without symlink traversal qualify.
MAX_WITNESS_LOG_BYTES=1024*1024
CYCLE_FILES=(
    ("flush-ack.serial","flush_ack_serial_log_sha256"),
    ("power-cut.serial","witness_cut_log_sha256"),
    ("reboot.serial","post_reboot_serial_log_sha256"),
)
NEGATIVE_FILES=("flush-fault","flush-sticky")


def verify_raw_evidence_bundle(report,evidence_root):
    """Hash all 3x3 independent cycle + 2 negative original file logs.

    This is file integrity, NOT evidence the experiment physically occurred.
    Parent and log components are opened relative to no-follow dir handles.
    """
    audit_report(report)
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
    folder_flags=flags|os.O_DIRECTORY
    hashes=[]
    count=0
    def check_one(folder_fd,name,expected,identifier):
        nonlocal count
        handle=os.open(name,flags,dir_fd=folder_fd)
        try:
            meta=os.fstat(handle)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_size<1 or
                    meta.st_size>MAX_WITNESS_LOG_BYTES):
                raise ValueError("unsafe or over-limit hardware witness file: "+identifier)
            with os.fdopen(os.dup(handle),"rb") as stream:
                contents=stream.read(MAX_WITNESS_LOG_BYTES+1)
            if len(contents)!=meta.st_size:
                raise ValueError("truncated hardware witness file: "+identifier)
            digest=hashlib.sha256(contents).hexdigest()
            if digest!=expected:
                raise ValueError("hardware evidence SHA mismatch: "+identifier)
            hashes.append(identifier+":"+digest)
            count+=1
        finally:
            os.close(handle)

    rootfd=os.open(os.fspath(evidence_root),folder_flags)
    try:
        for c in report["power_cycles"]:
            name=c["cycle_id"]  # already validated against strict safe-name regex
            fd=os.open(name,folder_flags,dir_fd=rootfd)
            try:
                for file_name,digest_key in CYCLE_FILES:
                    check_one(fd,file_name,c[digest_key],name+"/"+file_name)
            finally:
                os.close(fd)
        fd=os.open("negative",folder_flags,dir_fd=rootfd)
        try:
            for name in NEGATIVE_FILES:
                check_one(fd,name+".serial",
                    report["negative_cases"][name]["independent_event_log_sha256"],
                    "negative/"+name)
        finally:
            os.close(fd)
    finally:
        os.close(rootfd)
    return {
        "raw_log_digest_verified":True,
        "raw_logs_checked":count,
        "raw_logs_bundle_sha256":hashlib.sha256(
            "\\n".join(sorted(hashes)).encode("ascii")).hexdigest(),
    }


def verify_external_witness(report,pubkey_pem,pinned_der_sha256,signature,evidence_root=None):
    """Ed25519 signer authenticity (not proof the claimed experiment occurred)."""
    candidate=audit_report(report)
    require_hex(pinned_der_sha256,HEX64,"out-of-band witness key fingerprint")
    if not isinstance(pubkey_pem,bytes) or not isinstance(signature,bytes) or len(signature)!=64:
        raise ValueError("external witness public key/signature required")
    canonical=json.dumps(report,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    with tempfile.TemporaryDirectory() as temp:
        p=Path(temp)
        (p/"pub.pem").write_bytes(pubkey_pem)
        (p/"payload.json").write_bytes(canonical)
        (p/"sig.bin").write_bytes(signature)
        der=subprocess.run(["openssl","pkey","-pubin","-in",str(p/"pub.pem"),"-outform","DER"],
                           capture_output=True,timeout=10)
        if der.returncode:
            raise ValueError("invalid external witness public key")
        if hashlib.sha256(der.stdout).hexdigest()!=pinned_der_sha256:
            raise ValueError("witness public key differs from out-of-band trusted identity")
        check=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",
                              str(p/"pub.pem"),"-rawin","-in",str(p/"payload.json"),
                              "-sigfile",str(p/"sig.bin")],capture_output=True,timeout=10)
        if check.returncode:
            raise ValueError("external power-cut witness signature invalid")
    candidate["witness_signature_verified"]=True
    if evidence_root is not None:
        candidate.update(verify_raw_evidence_bundle(report,evidence_root))
        candidate["ready_for_independent_hardware_review"]=True
        candidate["scope"]="Signed device-specific bundle of raw SHA-verified log files; external physical event still requires independent human review"
    else:
        candidate["raw_log_digest_verified"]=False
        candidate["ready_for_independent_hardware_review"]=False
        candidate["scope"]="Signature valid but original power-cut/serial logs missing; not ready for physical review"
    return candidate


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report",type=Path)
    parser.add_argument("--trusted-public-key",type=Path,required=True)
    parser.add_argument("--trusted-key-sha256",required=True)
    parser.add_argument("--signature",type=Path,required=True)
    parser.add_argument("--evidence-directory",type=Path,required=True)
    args=parser.parse_args()
    report=json.loads(args.report.read_text())
    result=verify_external_witness(
        report,args.trusted_public_key.read_bytes(),args.trusted_key_sha256,
        args.signature.read_bytes(),evidence_root=args.evidence_directory)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
