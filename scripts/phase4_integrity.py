#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 4.2–4.4 integration gates; report only evidence actually inspected."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED = [
    ".github/workflows/d2-i225-regression.yml",
    ".github/workflows/driver-inventory.yml",
    ".github/workflows/driver-release-gates.yml",
    ".github/workflows/phase3-native-build.yml",
    "scripts/driver_inventory.py",
    "scripts/driver_release_matrix.py",
    "scripts/phase3-native-build.py",
    "sys/src/9/pc64/mkfile",
    "ryzova/metadata/kernel-version.json",
]
BANNED_SYNC = ".github/workflows/sync-9front.yml"
DRIVER_PATHS = ("sys/src/9/pc64/", "sys/src/9/port/", "sys/src/9/ip/", "ryzova/drivers/")
def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def evaluate(root=ROOT):
    checks = {}
    missing = [p for p in REQUIRED if not (root / p).is_file()]
    checks["driver_and_build_gates_present"] = not missing
    checks["upstream_auto_sync_absent"] = not (root / BANNED_SYNC).exists()
    meta = json.loads((root / "ryzova/metadata/kernel-version.json").read_text())
    contract = json.loads((root / "ryzova/sdk/kernel-contract.json").read_text())
    checks["experimental_abi_matches_kernel"] = (
        meta.get("abi") == contract.get("abi") and
        meta.get("status") == "experimental" and
        contract.get("stability") == "experimental" and
        contract.get("architecture") == "amd64")
    checks["does_not_claim_binary_compatibility"] = (
        contract.get("linux_binary_compatibility") is False and
        contract.get("windows_binary_compatibility") is False and
        contract.get("macos_binary_compatibility") is False)
    profile = json.loads((root / "ryzova/config/amd64-developer.json").read_text())
    checks["profile_is_non_release"] = (
        profile.get("architecture") == "amd64" and
        profile.get("release_ready") is False and
        profile.get("build_system") == "9front-mk" and
        profile.get("source_path") == "sys/src/9/pc64")
    checks["pinned_guest_image_digest"] = (
        len(profile.get("guest_image_sha256", "")) == 64 and
        all(c in "0123456789abcdef" for c in profile["guest_image_sha256"]))
    files = {p: digest(root / p) for p in REQUIRED if (root / p).is_file()}
    return {
        "schema": "ryzova-phase4-integrity/v1",
        "checks": checks,
        "pass": all(checks.values()),
        "missing": missing,
        "file_sha256": files,
        "scope": "Static integration and provenance only; not a new driver or QEMU boot test",
        "unverified": ["physical devices", "cross-host reproducible kernel binary",
                       "stable third-party ABI", "driver hotplug", "release clearance"]
    }
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--report", default="artifacts/phase4/integrity.json")
    a=ap.parse_args()
    result=evaluate()
    target=ROOT / a.report
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(json.dumps(result["checks"], indent=2, sort_keys=True))
    return 0 if result["pass"] else 1
if __name__ == "__main__":
    sys.exit(main())
