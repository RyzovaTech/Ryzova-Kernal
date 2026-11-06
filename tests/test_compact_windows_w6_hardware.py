# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from pathlib import Path
import tempfile
import unittest

from test_compact_windows_w6 import serial
from compact_windows_hardware import ASSETS, BOOT, CASES, SCHEMA, STAGE, json_bytes, verify
from compact_windows_w6_native import case_specs


class PhysicalBenchEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.bundle = Path(temp.name)
        hashes = {}
        for name in ASSETS:
            data = name.encode()
            (self.bundle / name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        raw = json_bytes({"schema": SCHEMA, "build_source_commit": "a"*40,
                          "fixture_source_commit": "b"*40, "sha256": hashes})
        (self.bundle / "manifest.json").write_bytes(raw)
        run_id = hashlib.sha256(raw).hexdigest()[:24]
        lines = [f"CW_HW_BEGIN_{run_id}", "Ryzova Kernel 0.1.0-dev", "9front-derived",
                 "experimental-0", "CW_HW_CPU amd64"]
        for name, digest in hashes.items():
            path = BOOT if name == "9pc64" else f"{STAGE}/{name}"
            lines.append(f"{digest}\t{path}")
        specs = case_specs()
        self.capture = ("\n".join(lines) + "\n").encode()
        self.capture += serial({name: specs[name] for name in CASES})
        self.capture += f"CW_HW_END_{run_id}\n".encode()
        self.hardware = dict(operator_observed_bare_metal=True,
                             operator_booted_kernel_from_bundle=True,
                             machine_model="bench model", cpu_model="Intel bench CPU",
                             firmware_version="test firmware", boot_device="test disk")

    def test_complete_capture_is_scoped_to_console_bench(self):
        result = verify(self.bundle, self.capture, self.hardware)
        self.assertEqual(tuple(result["cases"]), CASES)
        self.assertFalse(result["storage_power_loss_qualified"])

    def test_capture_rejects_wrong_hash_echo_and_duplicated_case(self):
        for capture in (
            self.capture.replace(BOOT.encode(), b"/tmp/9pc64"),
            self.capture.replace(b"CW_CASE_api_BEGIN", b"term% echo CW_CASE_api_BEGIN"),
            self.capture.replace(b"CW_CASE_api_END", b"CW_CASE_api_END\nCW_CASE_api_END"),
        ):
            with self.subTest(capture=capture[-100:]), self.assertRaises(ValueError):
                verify(self.bundle, capture, self.hardware)

    def test_reject_virtual_or_unattested_boot_and_tampered_bundle(self):
        for overrides in ({"boot_device": "QEMU disk"}, {"operator_booted_kernel_from_bundle": False}):
            with self.assertRaises(ValueError):
                verify(self.bundle, self.capture, self.hardware | overrides)
        (self.bundle / "api.exe").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            verify(self.bundle, self.capture, self.hardware)
