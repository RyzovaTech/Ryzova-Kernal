# SPDX-License-Identifier: GPL-3.0-only
"""W6 source/serial evidence gate: synthetic fixtures are only unit inputs."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_w4 import PAYLOAD
from compact_windows_w6_native import PIN,case_specs,fault_specs
from compact_windows_w6_acceptance import check,TRUE_FLAGS,FALSE_FLAGS
from test_compact_windows_w6 import serial


class VirtualEvidenceValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source="1"*40
        cls.runtime="a"*64
        cls.resource="b"*64
        cls.file="c"*64
        cls.durable=hashlib.sha256(PAYLOAD).hexdigest()
        fresh=serial(case_specs())
        fault=serial(fault_specs())
        cls.logs={
          "build-serial.log":b"CW_NATIVE_BUILD_OK\nCW_KERNEL_BUILD_OK\nCW_KERNEL_COPY_OK\n",
          "fresh-serial.log":(
              b"Ryzova Kernel 0.1.0-dev\n"
              b"CW_BARRIER_LOCAL_ONLY_OK\nCW_BARRIER_SERVICE_OK\n"
              b"CW_NAMESPACE_ISOLATION_OK\nCW_RUNTIME_DONE\n"+fresh),
          "reboot-serial.log":(
              b"Ryzova Kernel 0.1.0-dev\n"+
              cls.runtime.encode()+b"  /amd64/bin/compact-windows\n"
              b"CW_REBOOT_IDENTITY_OK\nCW_REBOOT_RESOURCE_MOUNTED\n"+
              cls.durable.encode()+b"  /tmp/cw-durable/payload.bin\n"
              b"CW_REBOOT_DONE\n"),
          "fault-serial.log":(
              b"Ryzova Kernel 0.1.0-dev\nCW_FAULT_MOUNTED\nCW_FAULT_CLEAN_OK\n"+
              cls.file.encode()+b"  /tmp/cw-file.exe\n"+fault),
        }
        cls.report={
          "schema":"compact-windows-w6-native/v1",
          "source_commit":cls.source,
          "bootstrap_image_gzip_sha256":PIN,
          "flush_evidence_scope":"dedicated QEMU virtio-SCSI disk; pinned cw-hjfs ACK after dirty cache drain and SYNCHRONIZE CACHE; no physical power-loss claim",
          "fixture_sha256":{k:cls.file for k in ("file","api","heap-limit","io-limit","handle-limit","ramfs-io")},
          "file_sha256":hashlib.sha256(b"FLEX_WINDOWS_W4_FILE_OK\n").hexdigest(),
          "durable_file_sha256":cls.durable,
          "cases":{},
        }
        for field in ("source_archive_sha256","kernel_sha256","bootstrap_image_sha256","resource_server_sha256","storage_fault_config_sha256"):
            cls.report[field]="d"*64
        cls.report["runtime_sha256"]=cls.runtime
        cls.report.update({k:True for k in TRUE_FLAGS})
        cls.report.update({k:False for k in FALSE_FLAGS})
        from compact_windows_w6_native import parse_cases
        cls.report["cases"]={**parse_cases(fresh,case_specs()),**parse_cases(fault,fault_specs())}

    def test_positive_synthetic_contract_is_bounded_not_full_release(self):
        r=check(copy.deepcopy(self.report),dict(self.logs),self.source)
        self.assertEqual(r["native_cases"],22)
        self.assertTrue(r["bounded_amd64_qemu_22_case_qualified"])
        self.assertFalse(r["physical_hardware_qualified"])
        self.assertFalse(r["full_w6_complete"])
        self.assertFalse(r["merge_authorized"])

    def test_mutated_receipts_fail_closed(self):
        edits=[
            ("source_commit","2"*40),("schema","unknown"),
            ("native_file_flush_qualified",False),
            ("storage_flush_failure_and_sticky_error_verified",False),
            ("physical_hardware_qualified",True),
            ("boot_root_sigkill_persistence_qualified",True),
            ("full_w6_complete",True),
            ("durable_file_sha256","f"*64),
            ("runtime_sha256","f"*64),
        ]
        for key,value in edits:
            with self.subTest(field=key),self.assertRaises(ValueError):
                report=copy.deepcopy(self.report);report[key]=value
                check(report,dict(self.logs),self.source)
        with self.assertRaises(ValueError):
            check(self.report,self.logs,"2"*40)

    def test_logs_and_guest_cases_cannot_be_omitted_or_spoofed(self):
        for key in self.logs:
            with self.subTest(log=key),self.assertRaises(ValueError):
                logs=dict(self.logs);logs[key]=b""
                check(self.report,logs,self.source)
        cases=["durable","flush-fault","flush-sticky","handle-limit"]
        for name in cases:
            with self.subTest(case=name),self.assertRaises(ValueError):
                report=copy.deepcopy(self.report)
                report["cases"].pop(name)
                check(report,dict(self.logs),self.source)
        for logkey,needle in (
            ("reboot-serial.log",self.durable.encode()),
            ("fault-serial.log",self.file.encode()),
            ("fresh-serial.log",b"CW_BARRIER_SERVICE_OK"),
            ("fault-serial.log",b"CW_FAULT_CLEAN_OK"),
        ):
            with self.subTest(source=logkey),self.assertRaises(ValueError):
                logs=dict(self.logs);logs[logkey]=logs[logkey].replace(needle,b"missing")
                check(self.report,logs,self.source)


if __name__=="__main__":
    unittest.main()
