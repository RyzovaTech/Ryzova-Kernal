# SPDX-License-Identifier: AGPL-3.0-only
"""W9 unsigned candidate and tampering tests; NEVER a hardware experiment."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
sys.path.insert(0,str(ROOT/"tests"))
from compact_windows_w9_lab_bundle import assemble_report, CYCLE_FILES
from test_compact_windows_physical_powercut import fixture, build_fake_raw_logs


def without_claimed_log_hashes(report):
    item=copy.deepcopy(report)
    for c in item["power_cycles"]:
        for _, field in CYCLE_FILES:
            c.pop(field,None)
    for key in ("flush-fault","flush-sticky"):
        item["negative_cases"][key].pop("independent_event_log_sha256",None)
    return item


class W9UnsignedLabKitTests(unittest.TestCase):
    def test_prepare_raw_log_hashes_never_certifies_physical_hardware(self):
        with tempfile.TemporaryDirectory() as temp:
            data=build_fake_raw_logs(fixture(),temp)
            report,receipt=assemble_report(without_claimed_log_hashes(data),temp)
            self.assertEqual(receipt["raw_logs"],11)
            self.assertEqual(receipt["source_commit"],data["source_commit"])
            self.assertTrue(receipt["raw_logs_sha256_verified"])
            self.assertFalse(receipt["external_signature_present"])
            self.assertFalse(receipt["physical_hardware_qualified"])
            self.assertFalse(receipt["ready_for_independent_hardware_review"])
            self.assertFalse(receipt["full_windows_v1_release_qualified"])
            self.assertEqual(
                report["power_cycles"][0]["flush_ack_serial_log_sha256"],
                data["power_cycles"][0]["flush_ack_serial_log_sha256"])
            self.assertEqual(
                json.loads(json.dumps(report,sort_keys=True,separators=(",",":"))),
                report)

    def test_refuses_modified_existing_hash_and_log_file(self):
        with tempfile.TemporaryDirectory() as temp:
            data=build_fake_raw_logs(fixture(),temp)
            data["power_cycles"][0]["witness_cut_log_sha256"]="0"*64
            with self.assertRaisesRegex(ValueError,"claimed SHA"):
                assemble_report(data,temp)
            data=without_claimed_log_hashes(data)
            (Path(temp)/"cycle-3"/"reboot.serial").unlink()
            with self.assertRaises(OSError):
                assemble_report(data,temp)

    def test_rejects_symlinked_raw_controller_log(self):
        with tempfile.TemporaryDirectory() as temp:
            data=build_fake_raw_logs(fixture(),temp)
            fake=Path(temp)/"cycle-1"/"power-cut.serial"
            fake.unlink()
            fake.symlink_to(Path(temp)/"cycle-2"/"power-cut.serial")
            with self.assertRaises(OSError):
                assemble_report(without_claimed_log_hashes(data),temp)

    def test_refuses_forged_observations_wrong_counter_and_duplicate_cycles(self):
        with tempfile.TemporaryDirectory() as temp:
            data=build_fake_raw_logs(fixture(),temp)
            originals=without_claimed_log_hashes(data)
            for mutate in (
                lambda x: x["power_cycles"][0].update(power_absent_measured=False),
                lambda x: x["power_cycles"][1].update(flush_acked=False),
                lambda x: x["power_cycles"][1].update(independent_controller_event_counter=1),
                lambda x: x.update(architecture="arm64"),
                lambda x: x.update(full_windows_compatibility=True),
            ):
                d=copy.deepcopy(originals)
                mutate(d)
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):
                    assemble_report(d,temp)
            bad=copy.deepcopy(originals)
            bad["power_cycles"][1]["cycle_id"]="cycle-1"
            with self.assertRaises(ValueError):
                assemble_report(bad,temp)

    def test_raw_logs_are_untrusted_even_with_all_signed_candidate_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            report=build_fake_raw_logs(fixture(),temp)
            _,receipt=assemble_report(report,temp)
            self.assertFalse(receipt["physical_hardware_qualified"])
            self.assertIn("UNSIGNED",receipt["scope"])


if __name__=="__main__":
    unittest.main()
