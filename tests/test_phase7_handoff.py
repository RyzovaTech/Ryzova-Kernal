# SPDX-License-Identifier: AGPL-3.0-only
"""Adversarial source, 9P and kernel provenance cross-checks."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from phase6_native_9p import payload_for_commit
from phase7_handoff import inspect, CHECKS

COMMIT = "a" * 40
KERNEL_HASH = "b" * 64


def documents():
    return {
        "phase6-native-9p.json": {
            "schema": "ryzova-phase6-native-9p-qemu/v1",
            "source_commit": COMMIT,
            "payload_sha256": hashlib.sha256(payload_for_commit(COMMIT)).hexdigest(),
            "passed": True, "host_9p_frames": 9,
            "checks": dict.fromkeys(CHECKS, True),
        },
        "kernel-provenance.json": {
            "source_commit": COMMIT,
            "guest_compiled_sha256": KERNEL_HASH,
            "guest_installed_sha256": KERNEL_HASH,
            "independently_extracted_host_sha256": KERNEL_HASH,
            "distribution_status": "BLOCKED pending licensing review",
        },
        "result.txt": (
            "Source SHA: " + COMMIT + "\n"
            "V2 native source compilation: PASS\n"
            "V3 rc userspace command verified: True\n"
            "V6 source-built QEMU guest network 9P mount and SHA: True\n"
        ),
    }


class Phase7HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "artifacts" / "phase3"
        self.out.mkdir(parents=True)

    def write(self, inputs):
        for file, data in inputs.items():
            (self.out / file).write_text(
                data if isinstance(data, str) else json.dumps(data),
                encoding="utf-8")

    def test_valid_coherent_runner_output(self):
        self.write(documents())
        result = inspect(self.root, COMMIT)
        self.assertTrue(result["ready"], result)
        for claim in ("native_tls_authentication_proven", "external_physical_peer_proven",
                      "remote_ram_proven", "remote_cpu_proven", "public_release_permitted"):
            self.assertFalse(result[claim])

    def test_no_forged_qemu_success_flag(self):
        d = documents()
        d["phase6-native-9p.json"]["passed"] = False
        self.write(d)
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_missing_real_tcp_frame_count(self):
        d = documents()
        d["phase6-native-9p.json"]["host_9p_frames"] = 0
        self.write(d)
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_wrong_guest_file_hash(self):
        d = documents()
        d["phase6-native-9p.json"]["payload_sha256"] = "0" * 64
        self.write(d)
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_changed_guest_kernel_binary(self):
        d = documents()
        d["kernel-provenance.json"]["guest_installed_sha256"] = "c" * 64
        self.write(d)
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_missing_serial_run_result(self):
        d = documents()
        d.pop("result.txt")
        self.write(d)
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_forged_other_commit(self):
        self.write(documents())
        self.assertFalse(inspect(self.root, "c" * 40)["ready"])

    def test_source_build_marker_is_required(self):
        d = documents()
        d["result.txt"] = d["result.txt"].replace("V2 native source compilation: PASS",
                                                   "V2 native source compilation: FAIL")
        self.write(d)
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_missing_any_native_step(self):
        for name in CHECKS:
            with self.subTest(check=name):
                d = documents()
                d["phase6-native-9p.json"]["checks"][name] = False
                self.write(d)
                self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_fail_closed_on_missing_inputs(self):
        self.assertFalse(inspect(self.root, COMMIT)["ready"])

    def test_reject_invalid_commit(self):
        with self.assertRaises(ValueError):
            inspect(self.root, "not a SHA")


if __name__ == "__main__":
    unittest.main()
