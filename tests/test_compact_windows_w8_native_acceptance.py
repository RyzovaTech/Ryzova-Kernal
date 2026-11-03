# SPDX-License-Identifier: AGPL-3.0-only
"""W8 acceptance parser synthetic-negative tests; not native QEMU evidence."""
import copy
import hashlib
import sys
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_w8_native_acceptance import accept
from compact_windows_w6_native import parse_cases


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sample(binary):
    head="c"*40
    pe=sha(binary)
    input_hash=sha(b"alpha beta\nsecond\n")
    out_hash=sha(b"2 3 18\n")
    log=(
        "Ryzova Kernel 0.1.0-dev\n"
        +pe+" /tmp/cw-w8wc.exe\n"
        +input_hash+" /tmp/cw-w8-input\n"
        +"CW_CASE_w8wc_BEGIN\n"
        +"CW_NATIVE status=0 exited=1 executed=1 guest=1048576 open=0 code=0 steps=444\n"
        +"CW_OUT 3220332031380a\n"
        +"CW_ERR \n"
        +"CW_CALL GetStdHandle 1\n"
        +"CW_CALL ReadFile 19\n"
        +"CW_CALL WriteFile 7\n"
        +"CW_CALL ExitProcess 1\n"
        +"CW_CASE_w8wc_END\n"
    ).encode()
    cases=parse_cases(log,{"w8wc":{"status":0,"code":0,
                                  "out":b"2 3 18\n".hex(),"err":""}})
    nested={
        "schema":"compact-windows-w8-native/v1",
        "source_commit":head,
        "windows_reference_pe_sha256":pe,
        "guest_pe_sha256":pe,
        "stdin_sha256":input_hash,
        "expected_stdout_sha256":out_hash,
        "native_qemu_case":cases["w8wc"],
        "native_qemu_same_windows_pe_verified":True,
        "native_qemu_stdin_stdout_exit_verified":True,
        "transitive_windows_runtime_qualified":False,
        "windows_v1_release_qualified":False,
        "physical_hardware_qualified":False,
        "general_windows_compatibility":False,
    }
    native={
        "schema":"compact-windows-w6-native/v1",
        "source_commit":head,
        "native_amd64_qemu_qualified":True,
        "w8_source_available_app":nested,
    }
    win={
        "schema":"compact-windows-w8-sbase-wc-host/v1",
        "source_commit":head,
        "windows_reference_qualified":True,
        "no_crt_candidate":{
            "windows_reference_default_passed":True,
            "candidate_structurally_eligible_for_native_investigation":True,
            "direct_imports":5,
            "missing_or_ordinal_imports":[],
            "native_guest_execution_qualified":False,
            "source_binary_sha256":pe,
        },
    }
    return native,win,log,head


class WindowsW8NativeAcceptanceTests(unittest.TestCase):
    def test_independent_parser_checks_sha_stdin_output_and_api_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/"real-pe-from-Windows-host.exe"
            binary.write_bytes(b"MZ"+bytes(1024))
            native,win,serial,head=sample(binary.read_bytes())
            receipt=accept(native,win,binary,serial,head)
            self.assertEqual(receipt["native_cases"],1)
            self.assertTrue(receipt["genuine_mit_sbase_wc_ascii_profile_qualified"])
            self.assertFalse(receipt["full_windows_v1_release_qualified"])
            self.assertFalse(receipt["merge_authorized"])

    def test_tampered_binary_unmatched_git_head_and_missing_logs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/"binary.exe"
            binary.write_bytes(b"MZ"+bytes(1024))
            original=binary.read_bytes()
            native,win,serial,head=sample(original)
            examples=[
                (native,win,serial,head[:-1]+"0"),
                (native,win,serial.replace(b"CW_CASE_w8wc_END",b"BAD_END"),head),
                (native,win,serial.replace(b"CW_CALL ReadFile 19",b"CW_CALL ReadFile 0"),head),
                (native,win,serial.replace(b" /tmp/cw-w8-input",b" /tmp/evil-input"),head),
            ]
            for n,w,log,h in examples:
                with self.subTest(head=h,length=len(log)):
                    with self.assertRaises(ValueError):
                        accept(n,w,binary,log,h)
            binary.write_bytes(original+b"corruption")
            with self.assertRaisesRegex(ValueError,"PE changed"):
                accept(native,win,binary,serial,head)

    def test_forged_release_and_unverified_guest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/"binary.exe"
            binary.write_bytes(b"MZ"+bytes(1024))
            native,win,log,head=sample(binary.read_bytes())
            edits=[
                lambda n,w:n["w8_source_available_app"].update(windows_v1_release_qualified=True),
                lambda n,w:n["w8_source_available_app"].update(guest_pe_sha256="a"*64),
                lambda n,w:w["no_crt_candidate"].update(native_guest_execution_qualified=True),
                lambda n,w:n.update(native_amd64_qemu_qualified=False),
                lambda n,w:w["no_crt_candidate"].update(missing_or_ordinal_imports=["user32.dll!Unknown"]),
            ]
            for edit in edits:
                n,w=copy.deepcopy(native),copy.deepcopy(win)
                edit(n,w)
                with self.subTest(edit=edit):
                    with self.assertRaises(ValueError):
                        accept(n,w,binary,log,head)


if __name__=="__main__":
    unittest.main()
