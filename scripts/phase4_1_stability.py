#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded Phase 4.1 memory, process, scheduler and kernel-access QEMU checks.

Commands are native Plan 9 rc, run ONLY after a newly compiled Ryzova kernel
boots under QEMU. This module is a test specification, not a driver patch.
"""
from __future__ import annotations

import re

ALLOC_BYTES = 128 * 4096  # 512 KiB (bounded, safe within the 2 GiB QEMU guest)

# Stage indices continue after Phase 3's 9P/storage/network stages (0-4).
# Every command emits a completion marker even if an earlier command fails:
# the host MUST independently check all positive evidence.
STAGES = (
    (
        "memory-before",
        "echo RYZOVA_SWAP_BEFORE_BEGIN; cat /dev/swap; "
        "echo RYZOVA_SWAP_BEFORE_END; echo RYZOVA_RUNTIME_STAGE_5",
    ),
    (
        "bounded-memory-io",
        "dd -if /dev/zero -of /tmp/ryzova-9p/phase41.mem "
        "-bs 4096 -count 128 > /tmp/phase41-dd.log >[2=1]; "
        "wc -c /tmp/ryzova-9p/phase41.mem; echo RYZOVA_RUNTIME_STAGE_6",
    ),
    (
        "process-lifecycle",
        "sleep 0.1 & wait $apid && echo RYZOVA_PROCESS_WAIT_OK; "
        "echo RYZOVA_RUNTIME_STAGE_7",
    ),
    (
        "scheduler-cooperative-progress",
        "sleep 0.3 & a=$apid; sleep 0.3 & b=$apid; "
        "wait $a && wait $b && echo RYZOVA_SCHEDULER_WAIT_OK; "
        "echo RYZOVA_RUNTIME_STAGE_8",
    ),
    (
        "process-enumeration",
        "ps | grep rc > /dev/null && echo RYZOVA_PROC_ENUM_OK; "
        "echo RYZOVA_RUNTIME_STAGE_9",
    ),
    (
        "memory-after",
        "echo RYZOVA_SWAP_AFTER_BEGIN; cat /dev/swap; "
        "echo RYZOVA_SWAP_AFTER_END; echo RYZOVA_RUNTIME_DONE; echo RYZOVA_RUNTIME_STAGE_10",
    ),
)


def _standalone(output: bytes, marker: bytes) -> bool:
    """Reject echoed input commands: marker must be a line all by itself."""
    return bool(re.search(rb"(?:^|\r?\n)" + re.escape(marker) + rb"(?:\r?\n|$)", output))


def _section(output: bytes, start: bytes, end: bytes) -> bytes:
    match = re.search(
        rb"(?:^|\r?\n)" + re.escape(start) + rb"\r?\n"
        + rb"(.*?)"
        + rb"(?:\r?\n)" + re.escape(end) + rb"(?:\r?\n|$)",
        output, flags=re.DOTALL,
    )
    return match.group(1) if match else b""


def _mem_stats(payload: bytes) -> dict | None:
    if not payload:
        return None
    data = {}
    for key in (b"memory", b"pagesize"):
        match = re.search(rb"(?:^|\r?\n)(\d+)\s+" + key + rb"(?:\r?\n|$)", payload)
        if not match:
            return None
        data[key.decode()] = int(match.group(1))
    for key in (b"user", b"swap"):
        match = re.search(rb"(?:^|\r?\n)(\d+)/(\d+)\s+" + key + rb"(?:\r?\n|$)", payload)
        if not match:
            return None
        used, total = map(int, match.groups())
        data[key.decode() + "_used"] = used
        data[key.decode() + "_total"] = total
    return data


def check_stability_serial(serial: bytes) -> dict:
    """Return a fail-closed JSON-serializable report for fresh-boot serial bytes."""
    before = _mem_stats(_section(serial, b"RYZOVA_SWAP_BEFORE_BEGIN", b"RYZOVA_SWAP_BEFORE_END"))
    after = _mem_stats(_section(serial, b"RYZOVA_SWAP_AFTER_BEGIN", b"RYZOVA_SWAP_AFTER_END"))
    checks = {
        "memory_stats_before": before is not None,
        "memory_stats_after": after is not None,
        "memory_stats_consistent": False,
        "bounded_memory_allocation_512k": bool(re.search(
            rb"(?:^|\r?\n)\s*524288\s+/tmp/ryzova-9p/phase41\.mem(?:\r?\n|$)", serial
        )),
        "process_spawn_wait": _standalone(serial, b"RYZOVA_PROCESS_WAIT_OK"),
        "scheduler_two_waited_children": _standalone(serial, b"RYZOVA_SCHEDULER_WAIT_OK"),
        "live_process_enumeration": _standalone(serial, b"RYZOVA_PROC_ENUM_OK"),
        "stage_progress": all(
            _standalone(serial, f"RYZOVA_RUNTIME_STAGE_{n}".encode())
            for n in range(5, 10)
        ),
        "completed": _standalone(serial, b"RYZOVA_RUNTIME_DONE"),
    }
    if before and after:
        good_page = before["pagesize"] >= 1024 and before["pagesize"] <= 65536 and (
            before["pagesize"] & (before["pagesize"] - 1)
        ) == 0
        valid_ranges = all(
            0 <= stats[f"{key}_used"] <= stats[f"{key}_total"]
            and stats[f"{key}_total"] > 0
            for stats in (before, after)
            for key in ("user", "swap")
        )
        checks["memory_stats_consistent"] = bool(
            good_page and valid_ranges and before["memory"] >= 128 * 1024 * 1024
            and before["memory"] == after["memory"]
            and before["pagesize"] == after["pagesize"]
        )
    return {
        "suite": "Ryzova Kernel Phase 4.1 experimental AMD64 QEMU stability",
        "checks": checks,
        "passed": all(checks.values()),
        "memory_before": before,
        "memory_after": after,
        "stress_scope": {
            "guest_ram_mib": 2048,
            "qemu_vcpus": 2,
            "temporary_ramfs_bytes": ALLOC_BYTES,
            "process_test": "one waited child + two concurrently spawned, separately waited children",
            "timeout_policy": "QEMU runner enforces a deadline and always destroys the disposable VM",
        },
        "unverified": [
            "sustained memory pressure and kernel allocation failure recovery",
            "real-hardware SMP/preemption, NUMA and physical device interactions",
            "full process credential isolation, fuzzing and exploit resistance",
            "scheduler latency, fairness and starvation under extended contention",
        ],
    }
