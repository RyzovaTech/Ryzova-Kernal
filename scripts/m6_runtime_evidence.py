#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed M6 ARM64 runtime evidence consistency gate.

Reports are *observations*, not independently attested hardware facts.
No JSON/serial data can authorize physical device certification.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def sha_valid(value, bits=256):
    return isinstance(value, str) and bool((SHA40 if bits == 40 else SHA256).fullmatch(value))


def count_positive(value):
    return type(value) is int and value > 0


def object_value(data, key):
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def equal_digest(a, b):
    return sha_valid(a) and a == b


def evaluate(cross, boot, runtime, expected_sha):
    """Assess evidence progression, never infer hardware certification."""
    if not sha_valid(expected_sha, 40):
        raise ValueError("expected Git source commit must be a lowercase full SHA40")
    for report in (cross, boot, runtime):
        if not isinstance(report, dict):
            raise ValueError("each evidence input must be a JSON object")
    source = (cross.get("source_sha") == expected_sha
              and cross.get("cross_compiler_7c") == "pass"
              and cross.get("arm64_pci_driver_7c") == "pass")
    linked = (source and cross.get("arm64_paqfs_userspace") == "pass"
              and cross.get("arm64_factotum_userspace") == "pass"
              and cross.get("arm64_kernel_link") == "pass")
    kernel_digest = boot.get("source_built_kernel_sha256")
    boot_observed = (linked and boot.get("schema") == "ryzova-m5-arm64-native-qemu/v1"
                     and boot.get("source_sha") == expected_sha
                     and boot.get("arm64_kernel_link") == "pass"
                     and boot.get("independent_kernel_sha256_verified") is True
                     and sha_valid(kernel_digest)
                     and boot.get("arm64_qemu_boot_observed") is True
                     and boot.get("outcome") == "kernel-boot-observed")
    runtime_source = (boot_observed
                      and runtime.get("schema") == "ryzova-m6-arm64-guest-runtime/v1"
                      and runtime.get("source_sha") == expected_sha
                      and runtime.get("kernel_sha256") == kernel_digest)
    net = object_value(runtime, "virtio_net")
    network_observation = bool(
        runtime_source and net.get("driver") == "virtio-net"
        and count_positive(net.get("guest_rx_packets"))
        and count_positive(net.get("guest_tx_packets"))
        and count_positive(net.get("host_rx_packets"))
        and count_positive(net.get("host_tx_packets"))
        and equal_digest(net.get("host_tx_sha256"), net.get("guest_rx_sha256"))
        and equal_digest(net.get("guest_tx_sha256"), net.get("host_rx_sha256")))
    blk = object_value(runtime, "virtio_block")
    block_observation = bool(
        runtime_source and blk.get("driver") == "virtio-blk"
        and count_positive(blk.get("guest_written_bytes"))
        and blk.get("flush_acknowledged") is True
        and equal_digest(blk.get("guest_write_sha256"), blk.get("guest_readback_sha256"))
        and equal_digest(blk.get("guest_write_sha256"), blk.get("host_after_flush_sha256")))
    smp = object_value(runtime, "smp_irq")
    smp_observation = bool(runtime_source
        and type(smp.get("online_cpus")) is int and smp["online_cpus"] >= 2
        and count_positive(smp.get("delivered_irqs"))
        and smp.get("irq_storm_recovered") is True
        and smp.get("registration_race_passed") is True)
    dma = object_value(runtime, "dma_iommu")
    dma_observation = bool(runtime_source
        and dma.get("mapping_failure_rejected") is True
        and dma.get("dma_bounds_negative_passed") is True
        and dma.get("detach_cleanup_passed") is True)
    checks = {
        "native_arm64_source_compiled": bool(source),
        "arm64_paqfs_factotum_and_kernel_linked": bool(linked),
        "arm64_qemu_boot_observed": bool(boot_observed),
        "virtio_net_host_guest_digests_consistent_unattested": network_observation,
        "virtio_block_host_guest_digests_consistent_unattested": block_observation,
        "smp_irq_stress_observations_consistent_unattested": smp_observation,
        "dma_lifecycle_observations_consistent_unattested": dma_observation,
    }
    blockers = [key for key, ok in checks.items() if not ok]
    blockers.extend(("independent-runtime-attestation-required",
                     "physical-arm64-amd64-and-legacy-lab-certification-required",
                     "human-hardware-release-approval-required"))
    return {
        "schema": "ryzova-m6-runtime-evidence-gate/v1",
        "expected_source_sha": expected_sha,
        "checks": checks,
        "unattested_observations_are_not_certifications": True,
        "all_runtime_observations_consistent": all(checks.values()),
        "hardware_release_ready": False,
        "newly_certified_physical_models": 0,
        "blockers": blockers,
    }


def load_report(path):
    if path is None or not path.exists():
        return {}
    if not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("invalid or oversized evidence report")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("evidence report must be a JSON object")
    return data


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cross", type=Path)
    p.add_argument("--boot", type=Path)
    p.add_argument("--runtime", type=Path)
    p.add_argument("--expected-head", help="Exact git source commit SHA40")
    p.add_argument("--output", type=Path, default=Path("artifacts/m6/runtime-evidence.json"))
    p.add_argument("--enforce-runtime", action="store_true")
    args = p.parse_args()
    expected = args.expected_head or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    result = evaluate(load_report(args.cross), load_report(args.boot),
                      load_report(args.runtime), expected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if args.enforce_runtime and not result["all_runtime_observations_consistent"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
