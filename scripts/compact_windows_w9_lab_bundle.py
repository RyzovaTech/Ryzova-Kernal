# SPDX-License-Identifier: AGPL-3.0-only
"""W9: prepare a bounded, UNSIGNED physical-lab review candidate.

Original hardware/controller logs must be gathered out-of-band by a real
operator and independent power controller. This tool does not control a
PDU/relay, generate witness keys, sign manifests, run physical tests, or
ever qualify hardware; it only binds independently supplied source logs to
an explicit operator-provided event report before an external witness can
review and sign the canonical manifest.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from compact_windows_physical_powercut import (
    CYCLE_FILES, NEGATIVE_FILES, MAX_WITNESS_LOG_BYTES,
    audit_report, verify_raw_evidence_bundle
)

SOURCE_SCHEMA = "compact-windows-external-powercut/v1"
SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,48}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_INPUT_JSON = 128 * 1024


def bounded_file_hash(dir_fd, name):
    """Open every original serial evidence file without symlink traversal."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or
                not 1 <= info.st_size <= MAX_WITNESS_LOG_BYTES):
            raise ValueError("non-regular/oversize physical log: " + name)
        with os.fdopen(os.dup(fd), "rb") as file:
            data = file.read(MAX_WITNESS_LOG_BYTES + 1)
        if len(data) != info.st_size:
            raise ValueError("physical lab log changed during collection: " + name)
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)


def bind_hash(target, field, observed):
    """Never silently rewrite an operator/witness's existing claimed SHA."""
    existing = target.get(field)
    if existing is not None and existing != observed:
        raise ValueError("original lab log disagrees with claimed SHA: " + field)
    target[field] = observed


def assemble_report(operator_report, raw_log_dir):
    """Prepare unsigned report from distinct physical logs; never set claims.

    Input booleans like power_absent_measured and cut_by_independent_controller
    are NOT set here and remain explicitly untrusted until external signing
    and review. The independent controller must supply them truthfully.
    """
    report = copy.deepcopy(operator_report)
    if not isinstance(report, dict) or report.get("schema") != SOURCE_SCHEMA:
        raise ValueError("unrecognised W9 lab report")
    cycles = report.get("power_cycles")
    if not isinstance(cycles, list) or not 3 <= len(cycles) <= 100:
        raise ValueError("three real independent cycles required")
    if not isinstance(report.get("negative_cases"), dict) or any(
        not isinstance(report["negative_cases"].get(key), dict)
        for key in NEGATIVE_FILES
    ):
        raise ValueError("missing real fault and sticky-error evidence")
    used = set()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY
    root = os.open(os.fspath(raw_log_dir), flags)
    try:
        for cycle in cycles:
            if not isinstance(cycle, dict):
                raise ValueError("invalid hardware cycle")
            name = cycle.get("cycle_id")
            if not isinstance(name, str) or not SAFE_ID.fullmatch(name) or name in used:
                raise ValueError("unsafe or repeated physical cycle identifier")
            used.add(name)
            folder = os.open(name, flags, dir_fd=root)
            try:
                for filename, field in CYCLE_FILES:
                    bind_hash(cycle, field, bounded_file_hash(folder, filename))
            finally:
                os.close(folder)
        negative = os.open("negative", flags, dir_fd=root)
        try:
            for key in NEGATIVE_FILES:
                bind_hash(
                    report["negative_cases"][key],
                    "independent_event_log_sha256",
                    bounded_file_hash(negative, key + ".serial")
                )
        finally:
            os.close(negative)
    finally:
        os.close(root)
    # Require the remaining time sequences, source commit, independent
    # controller event counters, device IDs, explicit observed ACK
    # and independently measured power absence from the supplied report.
    audit_report(report)
    receipt = verify_raw_evidence_bundle(report, raw_log_dir)
    if receipt.get("raw_logs_checked") != len(cycles)*3 + len(NEGATIVE_FILES):
        raise ValueError("physical lab log inventory not complete")
    return report, {
        "schema": "compact-windows-w9-unsigned-lab-package/v1",
        "source_commit": report["source_commit"],
        "raw_logs_sha256_verified": True,
        "raw_logs": receipt["raw_logs_checked"],
        "raw_logs_bundle_sha256": receipt["raw_logs_bundle_sha256"],
        "external_signature_present": False,
        "physical_hardware_qualified": False,
        "ready_for_independent_hardware_review": False,
        "full_windows_v1_release_qualified": False,
        "scope": "UNSIGNED candidate only; physical observations and independent signature not verified",
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--operator-report", type=Path, required=True)
    cli.add_argument("--raw-logs", type=Path, required=True)
    cli.add_argument("--unsigned-output", type=Path, required=True)
    args = cli.parse_args()
    if (not args.operator_report.is_file() or args.operator_report.is_symlink() or
            not 1 <= args.operator_report.stat().st_size <= MAX_INPUT_JSON):
        raise ValueError("untrusted lab manifest file")
    data = json.loads(args.operator_report.read_text(encoding="utf-8"))
    report, receipt = assemble_report(data, args.raw_logs)
    # This exact canonical byte encoding is what the independent external
    # Ed25519 signer may sign. Do not append a newline.
    payload = json.dumps(report, sort_keys=True, separators=(",",":"),
                         ensure_ascii=True).encode("ascii")
    if args.unsigned_output.exists():
        raise ValueError("never overwrite an existing signed/unsigned witness manifest")
    args.unsigned_output.write_bytes(payload)
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__=="__main__":
    main()
