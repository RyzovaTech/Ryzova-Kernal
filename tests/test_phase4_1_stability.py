#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed marker, metrics and bounded-test contract tests."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("phase41", ROOT / "scripts/phase4_1_stability.py")
phase41 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = phase41
spec.loader.exec_module(phase41)


def good_log() -> bytes:
    lines = [
        "term% echo RYZOVA_SWAP_BEFORE_BEGIN; cat /dev/swap; echo RYZOVA_SWAP_BEFORE_END",
        "RYZOVA_SWAP_BEFORE_BEGIN",
        "2147483648 memory",
        "4096 pagesize",
        "1200 kernel",
        "12000/240000 user",
        "300/900000 swap",
        "RYZOVA_SWAP_BEFORE_END",
        " 524288 /tmp/ryzova-9p/phase41.mem",
        "RYZOVA_PROCESS_WAIT_OK",
        "RYZOVA_SCHEDULER_WAIT_OK",
        "RYZOVA_PROC_ENUM_OK",
    ]
    lines.extend(f"RYZOVA_RUNTIME_STAGE_{n}" for n in range(5, 10))
    lines.extend([
        "RYZOVA_SWAP_AFTER_BEGIN",
        "2147483648 memory",
        "4096 pagesize",
        "1200 kernel",
        "12200/240000 user",
        "300/900000 swap",
        "RYZOVA_SWAP_AFTER_END",
        "RYZOVA_RUNTIME_DONE",
    ])
    return ("\r\n".join(lines) + "\r\n").encode()


class Phase41StabilityTests(unittest.TestCase):
    def test_bounded_stress_scope(self):
        self.assertEqual(phase41.ALLOC_BYTES, 524288)
        self.assertEqual(len(phase41.STAGES), 6)
        self.assertIn("wait $a && wait $b", phase41.STAGES[3][1])

    def test_valid_guest_log_passes(self):
        report = phase41.check_stability_serial(good_log())
        self.assertTrue(report["passed"], report["checks"])
        self.assertEqual(report["memory_before"]["pagesize"], 4096)
        self.assertTrue(report["checks"]["scheduler_two_waited_children"])

    def test_echoed_commands_are_not_accepted(self):
        raw = good_log().replace(b"\r\nRYZOVA_SCHEDULER_WAIT_OK\r\n", b"\r\n")
        raw += b"term% echo RYZOVA_SCHEDULER_WAIT_OK\r\n"
        report = phase41.check_stability_serial(raw)
        self.assertFalse(report["passed"])
        self.assertFalse(report["checks"]["scheduler_two_waited_children"])

    def test_missing_and_corrupted_memory_stats_fail(self):
        bad = good_log().replace(b"4096 pagesize", b"0 pagesize")
        self.assertFalse(phase41.check_stability_serial(bad)["passed"])
        bad = good_log().replace(b"12200/240000 user", b"240001/240000 user")
        self.assertFalse(phase41.check_stability_serial(bad)["passed"])

    def test_unbounded_or_incomplete_allocation_fails(self):
        bad = good_log().replace(b"524288 /tmp/ryzova-9p/phase41.mem",
                                b"524287 /tmp/ryzova-9p/phase41.mem")
        report = phase41.check_stability_serial(bad)
        self.assertFalse(report["checks"]["bounded_memory_allocation_512k"])

    def test_no_completion_marker_fails(self):
        bad = good_log().replace(b"\r\nRYZOVA_RUNTIME_DONE\r\n", b"\r\n")
        report = phase41.check_stability_serial(bad)
        self.assertFalse(report["passed"])
        self.assertFalse(report["checks"]["completed"])

    def test_plain_serial_string_does_not_pass(self):
        self.assertFalse(phase41.check_stability_serial(b"Plan 9\r\ninit: starting /bin/rc\r\n")["passed"])


if __name__ == "__main__":
    unittest.main()
