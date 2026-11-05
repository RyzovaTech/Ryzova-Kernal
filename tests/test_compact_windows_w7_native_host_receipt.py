# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed W7 actual Windows-ARM64-host receipt gate unit negatives.

Synthetic PE/JSON objects in this file only test receipt rejection. The
standalone CI Windows ARM64 job must actually execute original PE files.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_w7_native_host_triplet import (
    verify_windows_host_artifact, CASES, HOST_SCHEMA, EMPTY_SHA
)
from compact_windows_w7_arm64_qemu_user import sha256

HEAD="a"*40


def synthetic_pe(salt):
    data=bytearray(1024)
    data[:2]=b"MZ"
    struct.pack_into("<I",data,0x3c,0x80)
    data[0x80:0x84]=b"PE\x00\x00"
    struct.pack_into("<H",data,0x84,0xaa64)
    struct.pack_into("<H",data,0x86,1)
    struct.pack_into("<H",data,0x94,0xf0)
    struct.pack_into("<H",data,0x98,0x20b)
    struct.pack_into("<I",data,0x98+16,0x1000)
    struct.pack_into("<I",data,0x98+108,16)
    section=0x80+24+0xf0
    struct.pack_into("<I",data,section+12,0x1000)
    struct.pack_into("<I",data,section+16,0x200)
    struct.pack_into("<I",data,section+20,0x200)
    struct.pack_into("<I",data,section+36,0x60000020)
    struct.pack_into("<I",data,0x200,0xd65f03c0)
    data[0x210]=salt
    return bytes(data)


def fixture(directory):
    cases={}
    for num,(name,src) in enumerate(CASES.items(),1):
        raw=synthetic_pe(num)
        (directory/(name+".exe")).write_bytes(raw)
        cases[name]={
            "source_sha256":sha256(src.read_bytes()),
            "windows_arm64_pe_sha256":sha256(raw),
            "windows_arm64_pe_bytes":len(raw),
            "actual_windows_arm64_exit":37,
            "actual_windows_arm64_stdout_sha256":EMPTY_SHA,
            "actual_windows_arm64_stderr_sha256":EMPTY_SHA,
            "actual_windows_arm64_native_host_passed":True,
        }
    report={
        "schema":HOST_SCHEMA,"source_commit":HEAD,
        "windows_os_architecture":"Arm64",
        "windows_os_version":"test fixture only",
        "cases":cases,
        "actual_windows_arm64_host_reference_qualified":True,
        "native_ryzova_arm64_kernel_boot_qualified":False,
        "windows_v1_release_qualified":False,
        "physical_arm64_hardware_qualified":False,
    }
    save(directory,report)
    return report


def save(path,report):
    (path/"windows-arm64-reference.json").write_text(
        json.dumps(report)+"\n",encoding="utf-8")


class W7ActualWindowsArm64ReceiptTests(unittest.TestCase):
    def test_manifest_identity_sha_and_finite_four_cases(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            original=fixture(root)
            receipt,files=verify_windows_host_artifact(root,HEAD)
            self.assertEqual(receipt["source_commit"],HEAD)
            self.assertEqual(set(files),set(CASES))
            self.assertEqual(len(original["cases"]),4)

    def test_untrusted_binary_drift_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            original=fixture(root)
            name=next(iter(CASES))
            binary=root/(name+".exe")
            binary.write_bytes(binary.read_bytes()+b"unreviewed")
            with self.assertRaisesRegex(ValueError,"receipt mismatch"):
                verify_windows_host_artifact(root,HEAD)
            binary.write_bytes(synthetic_pe(1))
            # A different name cannot share the same PE hash.
            other=list(CASES)[1]
            original["cases"][other]["windows_arm64_pe_sha256"]=sha256(synthetic_pe(1))
            (root/(other+".exe")).write_bytes(synthetic_pe(1))
            save(root,original)
            with self.assertRaisesRegex(ValueError,"reused a PE"):
                verify_windows_host_artifact(root,HEAD)

    def test_forged_host_release_source_and_policy_are_rejected(self):
        operations=(
            lambda x:x.update(source_commit="b"*40),
            lambda x:x.update(windows_os_architecture="AMD64"),
            lambda x:x.update(native_ryzova_arm64_kernel_boot_qualified=True),
            lambda x:x.update(actual_windows_arm64_host_reference_qualified=False),
            lambda x:x.update(windows_v1_release_qualified=True),
            lambda x:x.update(physical_arm64_hardware_qualified=True),
            lambda x:x["cases"].pop(next(iter(CASES))),
            lambda x:x["cases"][next(iter(CASES))].update(actual_windows_arm64_exit=0),
            lambda x:x["cases"][next(iter(CASES))].update(actual_windows_arm64_stdout_sha256="0"*64),
            lambda x:x["cases"][next(iter(CASES))].update(source_sha256="0"*64),
        )
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            manifest=fixture(root)
            for i,operation in enumerate(operations):
                with self.subTest(attack=i):
                    altered=copy.deepcopy(manifest)
                    operation(altered)
                    save(root,altered)
                    with self.assertRaises(ValueError):
                        verify_windows_host_artifact(root,HEAD)
            save(root,manifest)
            with self.assertRaises(ValueError):
                verify_windows_host_artifact(root,"not-a-source-commit")


if __name__=="__main__":
    unittest.main()
