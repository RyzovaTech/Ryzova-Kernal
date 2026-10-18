#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded extra QEMU runtime probes, not a long-duration soak or security audit."""
import re
from phase4_1_stability import _mem_stats, _section, _standalone

STAGES = (
    ("extra-256k-ramfs-io",
     "dd -if /dev/zero -of /tmp/ryzova-9p/phase45.mem -bs 4096 -count 64 "
     "> /tmp/phase45-dd.log >[2=1]; wc -c /tmp/ryzova-9p/phase45.mem; "
     "echo RYZOVA_RUNTIME_STAGE_11"),
    ("three-child-progress",
     "sleep 0.2 & a=$apid; sleep 0.2 & b=$apid; sleep 0.2 & c=$apid; "
     "wait $a && wait $b && wait $c && echo RYZOVA_PHASE45_WAIT_OK; "
     "echo RYZOVA_RUNTIME_STAGE_12"),
    ("memory-observation",
     "echo RYZOVA_PHASE45_MEM_BEGIN; cat /dev/swap; "
     "echo RYZOVA_PHASE45_MEM_END; echo RYZOVA_RUNTIME_STAGE_13; "
     "echo RYZOVA_PHASE45_DONE"),
)

def check_extended_serial(serial: bytes) -> dict:
    stats = _mem_stats(_section(serial, b"RYZOVA_PHASE45_MEM_BEGIN",
                                b"RYZOVA_PHASE45_MEM_END"))
    reasonable = bool(stats and 1024 <= stats["pagesize"] <= 65536
        and stats["memory"] >= 128 * 1024 * 1024
        and all(0 <= stats[k + "_used"] <= stats[k + "_total"]
                and stats[k + "_total"] > 0 for k in ("swap", "user")))
    checks = {
        "additional_256k_ramfs_bytes": bool(re.search(
            rb"(?:^|\r?\n)\s*262144\s+/tmp/ryzova-9p/phase45\.mem(?:\r?\n|$)", serial)),
        "three_child_waits": _standalone(serial, b"RYZOVA_PHASE45_WAIT_OK"),
        "memory_counters_plausible": reasonable,
        "stage11_12_13": all(_standalone(serial, f"RYZOVA_RUNTIME_STAGE_{i}".encode())
                               for i in (11, 12, 13)),
        "completed": _standalone(serial, b"RYZOVA_PHASE45_DONE"),
        "no_observed_kernel_panic": re.search(rb"(?i)(?:kernel panic|^panic:)", serial, re.M) is None,
    }
    return {
        "schema": "ryzova-phase4-5-bounded/v1",
        "passed": all(checks.values()),
        "checks": checks,
        "scope": "2 vCPU QEMU guest, 256 KiB extra ramfs I/O and 3 waited children",
        "unverified": ["multi-hour soak", "memory exhaustion", "scheduler fairness",
                       "kernel fuzzing", "physical hardware", "privilege-escalation resistance"]
    }
