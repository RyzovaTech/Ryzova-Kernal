# SPDX-License-Identifier: AGPL-3.0-only
"""Hardware evidence integrity tests — NO physical power-cut is simulated."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from compact_windows_physical_powercut import (
    audit_report,verify_external_witness,verify_raw_evidence_bundle
)


def fixture():
    start=datetime(2026,11,2,6,0,tzinfo=timezone.utc)
    iso=lambda v:v.isoformat().replace("+00:00","Z")
    cycles=[]
    for i in range(3):
        t=start+timedelta(minutes=i*3)
        cycles.append({
            "cycle_id":"cycle-"+str(i+1),
            "flush_ack_nonce":("%016x"%(i+42)),
            "acknowledged_file_sha256":"a"*64,
            "post_reboot_file_sha256":"a"*64,
            "flush_ack_serial_log_sha256":"b"*64,
            "witness_cut_log_sha256":"c"*64,
            "post_reboot_serial_log_sha256":"d"*64,
            "flush_acked":True,
            "cut_by_independent_controller":True,
            "power_absent_measured":True,
            "cache_flush_command":"SCSI_SYNCHRONIZE_CACHE_10",
            "independent_controller_event_counter":i+100,
            "ack_utc":iso(t),
            "power_cut_utc":iso(t+timedelta(seconds=2)),
            "power_restored_utc":iso(t+timedelta(seconds=25)),
        })
    return {
        "schema":"compact-windows-external-powercut/v1",
        "source_commit":"1"*40,
        "architecture":"amd64",
        "target":"Ryzova Kernel",
        "device":{
            "controller_model":"disposable-scsi-controller",
            "controller_firmware":"firmware-1",
            "storage_model":"disposable-ssd",
            "storage_firmware":"ssd-fw-1",
            "power_cut_fixture_id":"independent-relay-1",
            "serial_sha256":"e"*64,
            "sector_bytes":512,
            "physical_cut_method":"external-power-controller",
        },
        "power_cycles":cycles,
        "negative_cases":{
            "flush-fault":{"win32_error":1117,"successful_flush_acks":0,"independent_event_log_sha256":"2"*64},
            "flush-sticky":{"win32_error":1117,"successful_flush_acks":0,"independent_event_log_sha256":"3"*64},
        },
        "full_windows_compatibility":False,
        "arm64_windows_qualified":False,
    }


def build_fake_raw_logs(record,root):
    """Synthetic corpus ONLY: no physical power-off was performed."""
    folder=Path(root)
    for cycle in record["power_cycles"]:
        d=folder/cycle["cycle_id"]
        d.mkdir(parents=True)
        for filename,field in (
            ("flush-ack.serial","flush_ack_serial_log_sha256"),
            ("power-cut.serial","witness_cut_log_sha256"),
            ("reboot.serial","post_reboot_serial_log_sha256"),
        ):
            message=(cycle["cycle_id"]+":"+filename+":UNIT-ONLY\\n").encode()
            (d/filename).write_bytes(message)
            cycle[field]=hashlib.sha256(message).hexdigest()
    d=folder/"negative"
    d.mkdir()
    for name in ("flush-fault","flush-sticky"):
        message=(name+":UNIT-ONLY\\n").encode()
        (d/(name+".serial")).write_bytes(message)
        record["negative_cases"][name]["independent_event_log_sha256"]=(
            hashlib.sha256(message).hexdigest())
    return record


class ExternalWitnessAuditTests(unittest.TestCase):
    def test_synthetic_report_only_creates_unqualified_review_candidate(self):
        record=audit_report(fixture())
        self.assertEqual(record["signed_external_cycles"],3)
        self.assertFalse(record["witness_signature_verified"])
        self.assertFalse(record["ready_for_independent_hardware_review"])
        self.assertFalse(record["physical_hardware_qualified"])
        self.assertFalse(record["general_windows_compatibility"])

    def test_faults_mutations_and_sigkill_cannot_promote_to_physical(self):
        for mutate in (
            lambda d:d.update(architecture="arm64"),
            lambda d:d["device"].update(physical_cut_method="qemu-sigkill"),
            lambda d:d["power_cycles"][1].update(post_reboot_file_sha256="0"*64),
            lambda d:d["power_cycles"][2].update(flush_ack_nonce=d["power_cycles"][0]["flush_ack_nonce"]),
            lambda d:d["power_cycles"][1].update(independent_controller_event_counter=100),
            lambda d:d["power_cycles"][0].update(flush_acked=False),
            lambda d:d["power_cycles"][0].update(power_absent_measured=False),
            lambda d:d["power_cycles"][0].update(ack_utc="bad-time"),
            lambda d:d["power_cycles"][0].update(power_cut_utc=d["power_cycles"][0]["ack_utc"]),
            lambda d:d["negative_cases"]["flush-sticky"].update(successful_flush_acks=1),
            lambda d:d.update(full_windows_compatibility=True),
            lambda d:d.update(arm64_windows_qualified=True),
            lambda d:d.update(power_cycles=d["power_cycles"][:2]),
        ):
            case=fixture()
            mutate(case)
            with self.subTest(mutant=str(mutate)),self.assertRaises(ValueError):
                audit_report(case)

    def test_all_original_raw_logs_required_and_bound_to_external_digests(self):
        with tempfile.TemporaryDirectory() as temp:
            record=build_fake_raw_logs(fixture(),Path(temp))
            result=verify_raw_evidence_bundle(record,temp)
            self.assertTrue(result["raw_log_digest_verified"])
            self.assertEqual(result["raw_logs_checked"],11)
            self.assertEqual(len(result["raw_logs_bundle_sha256"]),64)
            target=Path(temp)/"cycle-2"/"power-cut.serial"
            old=target.read_bytes()
            target.write_bytes(old+b"forged")
            with self.assertRaises(ValueError):
                verify_raw_evidence_bundle(record,temp)
            target.write_bytes(old)
            target.unlink()
            with self.assertRaises(OSError):
                verify_raw_evidence_bundle(record,temp)
            if hasattr(Path,"symlink_to"):
                (Path(temp)/"cycle-2"/"power-cut.serial").symlink_to(
                    Path(temp)/"cycle-1"/"power-cut.serial")
                with self.assertRaises(OSError):
                    verify_raw_evidence_bundle(record,temp)

    def test_signed_report_and_raw_files_still_only_candidate_for_review(self):
        if not shutil.which("openssl"):
            raise AssertionError("real OpenSSL Ed25519 implementation required")
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp)
            bundle=d/"witness-logs"
            bundle.mkdir()
            report=build_fake_raw_logs(fixture(),bundle)
            priv=d/"witness-private.pem"
            pub=d/"witness-public.pem"
            payload=d/"signed.json"
            sig=d/"signed.bin"
            subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(priv)],
                           check=True,capture_output=True,timeout=15)
            subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],
                           check=True,capture_output=True,timeout=15)
            der=subprocess.run(["openssl","pkey","-pubin","-in",str(pub),"-outform","DER"],
                               check=True,capture_output=True,timeout=15).stdout
            trusted=hashlib.sha256(der).hexdigest()
            payload.write_bytes(json.dumps(report,sort_keys=True,
                                separators=(",",":"),ensure_ascii=True).encode("ascii"))
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),
                            "-rawin","-in",str(payload),"-out",str(sig)],
                           check=True,capture_output=True,timeout=15)
            candidate=verify_external_witness(
                report,pub.read_bytes(),trusted,sig.read_bytes(),evidence_root=bundle)
            self.assertTrue(candidate["witness_signature_verified"])
            self.assertTrue(candidate["raw_log_digest_verified"])
            self.assertTrue(candidate["ready_for_independent_hardware_review"])
            self.assertFalse(candidate["physical_hardware_qualified"])
            self.assertFalse(candidate["general_windows_compatibility"])

    def test_external_ed25519_signature_tampering_and_independent_trust(self):
        if not shutil.which("openssl"):
            raise AssertionError("OpenSSL required: no signature verification bypass")
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)
            priv=path/"witness-private.pem"
            pub=path/"witness-public.pem"
            payload=path/"canonical.json"
            sig=path/"signature.bin"
            subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(priv)],
                           check=True,capture_output=True,timeout=15)
            subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],
                           check=True,capture_output=True,timeout=15)
            der=subprocess.run(["openssl","pkey","-pubin","-in",str(pub),"-outform","DER"],
                               check=True,capture_output=True,timeout=15).stdout
            trusted=hashlib.sha256(der).hexdigest()
            report=fixture()
            payload.write_bytes(json.dumps(report,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii"))
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),
                            "-rawin","-in",str(payload),"-out",str(sig)],
                           check=True,capture_output=True,timeout=15)
            proved=verify_external_witness(report,pub.read_bytes(),trusted,sig.read_bytes())
            self.assertTrue(proved["witness_signature_verified"])
            self.assertFalse(proved["ready_for_independent_hardware_review"])
            self.assertFalse(proved["raw_log_digest_verified"])
            self.assertFalse(proved["physical_hardware_qualified"])
            # Self-generated keys are synthetic tests, NOT trusted witnesses.
            with self.assertRaises(ValueError):
                verify_external_witness(report,pub.read_bytes(),"0"*64,sig.read_bytes())
            altered=copy.deepcopy(report)
            altered["power_cycles"][0]["post_reboot_file_sha256"]="0"*64
            with self.assertRaises(ValueError):
                verify_external_witness(altered,pub.read_bytes(),trusted,sig.read_bytes())
            altered=copy.deepcopy(report)
            altered["device"]["controller_model"]="different physical device"
            with self.assertRaises(ValueError):
                verify_external_witness(altered,pub.read_bytes(),trusted,sig.read_bytes())

if __name__=="__main__":
    unittest.main()
