#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M6.2 strict, non-certifying ARM64 VirtIO functional-I/O acceptance.

This is deliberately separate from the M6.1 native-kernel boot acceptance.
An installed device, a shell banner, or a synthetic fixture does NOT prove
a working network/data transfer or a functioning block write/read path.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


SCHEMA = "ryzova-m6-arm64-virtio-acceptance/v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")


def read_json(path):
    if not path.is_file() or path.stat().st_size > 1_000_000:
        raise ValueError("required evidence missing or oversized: " + str(path))
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("report is not a JSON object: " + str(path))
    return obj


def evaluate(boot, io, head):
    if not isinstance(head, str) or not SHA40.fullmatch(head):
        raise ValueError("checkout sha must be complete lower-case Git SHA-1")
    if not isinstance(boot, dict) or not isinstance(io, dict):
        raise ValueError("M6.1 and M6.2 reports must be objects")
    digest = boot.get("source_built_kernel_sha256")
    checks = {
        "same_exact_checkout": (
            boot.get("source_sha") == head and io.get("source_sha") == head
        ),
        "source_built_m6_1_aarch64_boot": (
            boot.get("schema") == "ryzova-m5-arm64-native-qemu/v1"
            and boot.get("arm64_kernel_link") == "pass"
            and boot.get("arm64_qemu_boot_observed") is True
            and boot.get("outcome") == "kernel-boot-observed"
            and boot.get("independent_kernel_sha256_verified") is True
            and isinstance(digest, str)
            and SHA64.fullmatch(digest) is not None
        ),
        "m6_2_boots_exact_native_uimage": (
            io.get("schema") == "ryzova-m6-arm64-virtio-functional/v1"
            and io.get("expected_uimage_sha256") == digest
            and io.get("verified_uimage_sha256") is True
        ),
        "virtio_guest_shell_observed": (
            io.get("guest_shell_reached") is True
            and io.get("qemu_virtio_devices_attached") is True
            and io.get("root_disk_copy_on_write") is True
        ),
        "host_http_and_guest_network_sha256": (
            io.get("http_guest_request_observed") is True
            and type(io.get("host_fixture_requests")) is int
            and io["host_fixture_requests"] >= 1
            and io.get("guest_network_digest_verified") is True
            and io.get("arm64_virtio_network_verified") is True
        ),
        "guest_write_read_and_host_disk_integrity": (
            io.get("guest_disk_write_status_ok") is True
            and io.get("guest_disk_read_digest_verified") is True
            and io.get("host_ephemeral_disk_write_verified") is True
            and io.get("arm64_virtio_storage_verified") is True
        ),
        "completed_actual_guest_virtio_functional_path": (
            io.get("outcome") == "guest-virtio-io-observed"
            and all(s in io.get("completed_guest_stages", [])
                    for s in (0, 1, 2, 3))
        ),
        "still_research_only_not_hardware_certified": (
            boot.get("release_status") == "blocked"
            and io.get("release_status") == "blocked"
            and type(boot.get("newly_certified_physical_models")) is int
            and boot.get("newly_certified_physical_models") == 0
            and type(io.get("newly_certified_physical_models")) is int
            and io.get("newly_certified_physical_models") == 0
            and io.get("physical_hardware_certified") is False
        ),
    }
    return {
        "schema": SCHEMA,
        "checkout_sha": head,
        "checks": checks,
        "m6_2_virtio_functional_accepted": all(checks.values()),
        "physical_hardware_certified": False,
        "newly_certified_physical_models": 0,
        "blockers": [key for key, accepted in checks.items() if not accepted],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--boot", required=True, type=Path)
    ap.add_argument("--virtio", required=True, type=Path)
    ap.add_argument("--expected-head")
    ap.add_argument("--output", type=Path,
                    default=Path("artifacts/phase3/m6-arm64-virtio-acceptance.json"))
    args = ap.parse_args()
    head = args.expected_head or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    try:
        result = evaluate(read_json(args.boot), read_json(args.virtio), head)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {
            "schema": SCHEMA, "checkout_sha": head,
            "m6_2_virtio_functional_accepted": False,
            "blockers": [str(exc)[:320]],
            "physical_hardware_certified": False,
            "newly_certified_physical_models": 0,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["m6_2_virtio_functional_accepted"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
