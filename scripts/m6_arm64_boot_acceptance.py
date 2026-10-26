#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M6.1 fail-closed gate for an *observed* native ARM64 QEMU boot.

This checks self-reported CI evidence consistency and cannot certify physical
hardware. Run only after the native cross-build and independent QEMU probe.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_LIBRARIES = (
    "libc", "libbio", "libflate", "libString", "libthread", "lib9p",
    "libmp", "libsec", "libip", "libdraw",
    "libmemdraw", "libmemlayer", "libauth", "libauthsrv",
)


def load(path):
    if not path.is_file() or path.stat().st_size > 1_000_000:
        raise ValueError("missing or oversized ARM64 evidence report: " + str(path))
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("ARM64 report must be a JSON object")
    return value


def evaluate(cross, boot, sha):
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        raise ValueError("expected source sha must be a complete lowercase SHA40")
    if not isinstance(cross, dict) or not isinstance(boot, dict):
        raise ValueError("ARM64 evidence inputs must be objects")
    libs = cross.get("arm64_bootstrap_libraries")
    if not isinstance(libs, dict):
        libs = {}
    checks = {
        "source_sha_matches_checkout": cross.get("source_sha") == sha and boot.get("source_sha") == sha,
        "arm64_native_7c_compiled": cross.get("cross_compiler_7c") == "pass"
            and cross.get("arm64_pci_driver_7c") == "pass",
        "all_target_libraries_built": (
            cross.get("arm64_bootstrap_libraries_complete") is True
            and all(libs.get(name) == "pass" for name in REQUIRED_LIBRARIES)
        ),
        "target_paqfs_factotum_linked": cross.get("arm64_paqfs_userspace") == "pass"
            and cross.get("arm64_factotum_userspace") == "pass",
        "arm64_native_kernel_linked": cross.get("arm64_kernel_link") == "pass"
            and boot.get("arm64_kernel_link") == "pass",
        "arm64_uimage_fat_copy_verified": cross.get("arm64_fat_copy_verified") is True,
        "arm64_uimage_digest_verified": (
            isinstance(cross.get("arm64_uimage_guest_sha256"), str)
            and HEX64.fullmatch(cross["arm64_uimage_guest_sha256"]) is not None
            and cross["arm64_uimage_guest_sha256"] == boot.get("source_built_kernel_sha256")
            and boot.get("independent_kernel_sha256_verified") is True
        ),
        "fresh_aarch64_qemu_boot_observed": (
            boot.get("schema") == "ryzova-m5-arm64-native-qemu/v1"
            and boot.get("arm64_qemu_boot_observed") is True
            and boot.get("outcome") == "kernel-boot-observed"
        ),
        "not_a_hardware_release": (
            boot.get("release_status") == "blocked"
            and type(boot.get("newly_certified_physical_models")) is int
            and boot.get("newly_certified_physical_models") == 0
        ),
    }
    return {
        "schema": "ryzova-m6-arm64-native-boot-acceptance/v1",
        "checkout_sha": sha,
        "checks": checks,
        "arm64_qemu_boot_accepted": all(checks.values()),
        "physical_hardware_certified": False,
        "newly_certified_physical_models": 0,
        "blockers": [name for name, value in checks.items() if not value],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cross", type=Path, required=True)
    ap.add_argument("--boot", type=Path, required=True)
    ap.add_argument("--expected-head")
    ap.add_argument("--output", type=Path,
                    default=Path("artifacts/phase3/m6-arm64-boot-acceptance.json"))
    args = ap.parse_args()
    sha = args.expected_head or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    try:
        result = evaluate(load(args.cross), load(args.boot), sha)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"schema": "ryzova-m6-arm64-native-boot-acceptance/v1",
                  "checkout_sha": sha, "arm64_qemu_boot_accepted": False,
                  "physical_hardware_certified": False,
                  "newly_certified_physical_models": 0,
                  "blockers": [str(exc)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["arm64_qemu_boot_accepted"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
