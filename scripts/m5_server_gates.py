#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M5.1-M5.3 evidence adjudication. Missing ARM64 target evidence fails closed.

Source checks and an x86_64 build never count as an ARM64 boot, VirtIO I/O,
multicore IRQ recovery, or physical server qualification.
"""
import argparse
import json
from pathlib import Path
import re
from m5_platform_audit import audit

ROOT=Path(__file__).resolve().parents[1]

def arm64_evidence(serial):
    """Accept separately marked real guest output lines, never shell echo."""
    if not isinstance(serial,(bytes,bytearray)):
        raise ValueError("ARM64 serial must be raw bytes")
    # Generic Plan 9 boot identity is not enough to certify Ryzova ARM64.
    evidence={
        "arm64_kernel_banner":bool(re.search(rb"(?:^|\r?\n)Plan 9(?:\r?\n)",serial)),
        "arm64_cpu_console":bool(re.search(rb"(?:^|\r?\n)cpu0:[^\r\n]{1,100}(?:\r?\n)",serial)),
        "virtio_net_datapath":bool(re.search(rb"(?:^|\r?\n)M5_ARM64_NET_IO_OK(?:\r?\n)",serial)),
        "virtio_storage_integrity":bool(re.search(rb"(?:^|\r?\n)M5_ARM64_DISK_SHA_OK(?:\r?\n)",serial)),
        "multicore_interrupt_recovery":bool(re.search(rb"(?:^|\r?\n)M5_ARM64_SMP_IRQ_OK(?:\r?\n)",serial)),
    }
    return evidence

def report(platform_report,cross=None,armserial=b""):
    if platform_report.get("arm64_native_boot_confirmed") is not False:
        raise ValueError("M5 readiness must not self-certify ARM64 boots")
    cross=cross or {}
    arm=arm64_evidence(armserial)
    cross_ok=cross.get("cross_compiler_7c")=="pass"
    link_ok=cross.get("arm64_kernel_link")=="pass"
    # The current runner has NO authenticated guest proof or signature chain.
    # Do not self-approve solely from a serial log with user-generated markers.
    return {
        "schema":"ryzova-m5-full-gates/v1",
        "m5_1_arm64_source_compiled":cross_ok,
        "m5_1_arm64_kernel_linked":link_ok,
        "m5_1_arm64_boot_certified":False,
        "m5_2_arm64_virtio_network_certified":False,
        "m5_2_arm64_virtio_storage_certified":False,
        "m5_3_arm64_smp_irq_dma_certified":False,
        "m5_3_amd64_server_physical_certified":False,
        "m5_4_legacy_amd64_preserved":True,
        "native_arm64_serial_observations_unattested":arm,
        "physical_hardware_models_newly_certified":0,
        "m5_full_complete":False,
        "ready_for_m6_planning":True,
        "ready_for_m6_hardware_release":False,
        "blockers":[
            "full ARM64 native kernel/bootfs link and QEMU boot",
            "authenticated ARM64 VirtIO network and block functional I/O",
            "ARM64 SMP/GIC/IRQ lifecycle and DMA/IOMMU isolation testing",
            "AMD64/ARM64 server and legacy AMD64 physical lab approval",
        ],
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cross-report",type=Path,default=None)
    parser.add_argument("--arm64-serial",type=Path,default=None)
    parser.add_argument("--output",type=Path,default=None)
    args=parser.parse_args()
    source=audit(ROOT)
    cross=json.loads(args.cross_report.read_text()) if args.cross_report and args.cross_report.exists() else None
    serial=args.arm64_serial.read_bytes() if args.arm64_serial and args.arm64_serial.exists() else b""
    result=report(source,cross,serial)
    out=json.dumps(result,indent=2,sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(out)
    else:
        print(out,end="")

if __name__=="__main__":
    main()
