#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 7 entry: cross-check native QEMU 9P and source-built kernel evidence.

This is a closeout reader of *actual runner-produced artifacts*. It is not an
alternative to, or substitute for, the native AMD64 QEMU test itself.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

from phase6_native_9p import payload_for_commit

ROOT = Path(__file__).resolve().parents[1]
HEX_SHA = re.compile(r"[a-f0-9]{64}\Z")
CHECKS = (
    "native_guest_file_contains_expected_commit_challenge",
    "guest_sha256_of_native_tcp_9p_file",
    "two_stages_completed",
    "native_9p_sequence_completed",
    "tcp_9p_server_exchanged_multiple_frames",
    "no_observed_kernel_panic",
)


def inspect(base: Path, commit: str) -> dict:
    """Check closed-world fields; missing or forged claims must never pass."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("an exact 40-character source commit is required")
    evidence_dir = base / "artifacts" / "phase3"
    inputs = ("phase6-native-9p.json", "kernel-provenance.json", "result.txt")
    try:
        p9 = json.loads((evidence_dir / inputs[0]).read_text(encoding="utf-8"))
        kernel = json.loads((evidence_dir / inputs[1]).read_text(encoding="utf-8"))
        result = (evidence_dir / inputs[2]).read_text(encoding="utf-8")
    except (OSError, ValueError, UnicodeError) as exc:
        return {"schema": "ryzova-phase7-entry-evidence/v1",
                "ready": False, "checks": {"all_runner_artifacts_available": False},
                "error": type(exc).__name__}
    source_hash = hashlib.sha256(payload_for_commit(commit)).hexdigest()
    digests = [kernel.get(key) for key in (
        "guest_compiled_sha256", "guest_installed_sha256",
        "independently_extracted_host_sha256")]
    checks = {
        "native_qemu_evidence_schema":
            p9.get("schema") == "ryzova-phase6-native-9p-qemu/v1",
        "evidence_source_commit_matches_checkout":
            p9.get("source_commit") == commit and kernel.get("source_commit") == commit
            and ("Source SHA: " + commit + "\n") in result,
        "host_guest_sha256_challenge_matches_checkout":
            p9.get("payload_sha256") == source_hash,
        "native_9p_positive_checks": p9.get("passed") is True
            and isinstance(p9.get("checks"), dict)
            and all(p9["checks"].get(key) is True for key in CHECKS),
        "actual_9p_tcp_frames": type(p9.get("host_9p_frames")) is int
            and p9["host_9p_frames"] >= 5,
        "source_built_kernel_guest_host_hashes_match":
            all(isinstance(value, str) and HEX_SHA.fullmatch(value) for value in digests)
            and len(set(digests)) == 1,
        "source_built_kernel_sha_reported":
            ("V2 native source compilation: PASS\n" in result)
            and ("V6 source-built QEMU guest network 9P mount and SHA: True\n" in result)
            and ("V3 rc userspace command verified: True\n" in result),
        "kernel_binary_public_distribution_blocked":
            "BLOCKED" in str(kernel.get("distribution_status", "")),
    }
    return {
        "schema": "ryzova-phase7-entry-evidence/v1",
        "source_commit": commit,
        "ready": all(checks.values()),
        "checks": checks,
        "kernel_sha256": digests[0] if len(set(map(str, digests))) == 1 else None,
        "test_file_sha256": source_hash,
        "native_tls_authentication_proven": False,
        "external_physical_peer_proven": False,
        "remote_ram_proven": False,
        "remote_cpu_proven": False,
        "public_release_permitted": False,
        "meaning": "verified research baseline for Phase 7, not production remote resource support",
    }


def main() -> int:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=ROOT, text=True).strip()
    report = inspect(ROOT, commit)
    out = ROOT / "artifacts" / "phase3" / "phase7-entry.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for name, ok in report["checks"].items():
        print("PHASE7 ENTRY", "PASS" if ok else "FAIL", name, flush=True)
    print("PHASE7 RESEARCH READY", report["ready"], flush=True)
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
