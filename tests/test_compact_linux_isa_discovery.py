# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-04 read-only ELF/RIP attribution tests, no compatibility bypass."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_linux_isa_discovery import (
    MAIN_PIE_BIAS, INTERP_BIAS, create_report, locate_candidate,
)


def minimal_elf(etype=3, vaddr=0x1000, prefix=b"\x0f\x57\xc0\xc3"):
    raw=bytearray(0x200)
    raw[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI",raw,16,etype,62,1)
    struct.pack_into("<Q",raw,32,64)
    struct.pack_into("<HHH",raw,52,64,56,1)
    struct.pack_into("<IIQQQQQQ",raw,64,1,5,0x100,vaddr,0,len(prefix),len(prefix),0x1000)
    raw[0x100:0x100+len(prefix)]=prefix
    return bytes(raw)


class IsaDiscoveryTests(unittest.TestCase):
    def test_pie_main_bytes_bound_to_actual_rip(self):
        binary=minimal_elf()
        result=locate_candidate(binary,MAIN_PIE_BIAS+0x1001,bias=MAIN_PIE_BIAS)
        self.assertEqual(result["candidate_bytes_hex"],"57c0c3")
        self.assertEqual(result["elf_file_offset"],0x101)
        self.assertTrue(result["segment_executable"])
        self.assertTrue(result["bytes_are_only_candidate"])

    def test_pinned_interpreter_fixed_bias(self):
        binary=minimal_elf()
        result=locate_candidate(binary,INTERP_BIAS+0x1000,bias=INTERP_BIAS)
        self.assertEqual(result["candidate_bytes_hex"],"0f57c0c3")
        self.assertIsNone(locate_candidate(binary,0x1000,bias=INTERP_BIAS))

    def test_elf_bounds_and_unsupported_locations_fail_closed(self):
        binary=minimal_elf(etype=2)
        for image,rip,bias in (
            (binary,0x1000,MAIN_PIE_BIAS),
            (binary,0x1004,0),
            (binary,-1,0),
            (binary,0x1000,-1),
            (binary[:-0x104],0x1000,0),
            (b"not-elf",0x1000,0),
            (binary,0x3000,0),
        ):
            with self.subTest(rip=rip,bias=bias):
                self.assertIsNone(locate_candidate(image,rip,bias=bias))

    def test_report_requires_real_digests_and_tracks_unknown_rip(self):
        raw=minimal_elf()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"bin").mkdir()
            (root/"bin/busybox").write_bytes(raw)
            target={"target":"busybox","elf":{"sha256":hashlib.sha256(raw).hexdigest()},
                    "guest_smoke_passed":False,
                    "guest_actual_result":{"last_rip_hex":hex(0x401000)[2:],"status":3}}
            result=create_report(root,{"targets":[target]})
            self.assertFalse(result["guest_linux_v1_complete"])
            self.assertEqual(result["reports"][0]["candidate"]["image"],"main")
            self.assertEqual(result["reports"][0]["candidate"]["candidate_bytes_hex"],
                             "0f57c0c3")
            successful={**target,"guest_smoke_passed":True}
            self.assertIsNone(create_report(root,{"targets":[successful]})
                              ["reports"][0]["candidate"])
            wrong={**target,"elf":{"sha256":"0"*64}}
            with self.assertRaises(ValueError):
                create_report(root,{"targets":[wrong]})
            gone={**target,"guest_actual_result":{"last_rip_hex":"deadbeef","status":3}}
            out=create_report(root,{"targets":[gone]})
            self.assertIsNone(out["reports"][0]["candidate"])

    def test_python_code_probe_has_independent_pinned_candidate(self):
        image=minimal_elf()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"usr/bin").mkdir(parents=True)
            (root/"usr/bin/python3.12").write_bytes(image)
            target={
                "target":"python","elf":{"sha256":hashlib.sha256(image).hexdigest()},
                "guest_smoke_passed":True,"guest_actual_result":{"last_rip_hex":"401000","status":0},
                "python_code_probe":{"passed":False,"actual":{"last_rip_hex":"401000","status":3}}
            }
            result=create_report(root,{"targets":[target]})
            self.assertEqual(len(result["reports"]),2)
            self.assertIsNone(result["reports"][0]["candidate"])
            failed=result["reports"][1]
            self.assertEqual(failed["target"],"python-code")
            self.assertEqual(failed["guest_actual_result"]["status"],3)
            self.assertEqual(failed["candidate"]["candidate_bytes_hex"],"0f57c0c3")
            self.assertFalse(result["guest_linux_v1_complete"])
            target["python_code_probe"]["passed"]=True
            self.assertIsNone(create_report(root,{"targets":[target]})
                              ["reports"][1]["candidate"])
            target["python_code_probe"]["passed"]=False
            target["elf"]["sha256"]="a"*64
            with self.assertRaises(ValueError):
                create_report(root,{"targets":[target]})

    def test_symlink_must_remain_beneath_locked_root(self):
        raw=minimal_elf()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"root"
            (root/"bin").mkdir(parents=True)
            real=root/"bin/x86_64-linux-musl-gcc"
            real.write_bytes(raw)
            (root/"bin/gcc").symlink_to("x86_64-linux-musl-gcc")
            record={"target":"gcc","elf":{"sha256":hashlib.sha256(raw).hexdigest()},
                    "guest_smoke_passed":False,
                    "guest_actual_result":{"last_rip_hex":"401000","status":3}}
            self.assertIsNotNone(create_report(root,{"targets":[record]})
                                 ["reports"][0]["candidate"])
            (root/"bin/gcc").unlink()
            outside=Path(d)/"outside"
            outside.write_bytes(raw)
            (root/"bin/gcc").symlink_to(outside)
            with self.assertRaises(ValueError):
                create_report(root,{"targets":[record]})

    def test_failure_console_lines_never_claim_opcode_support_or_guest_success(self):
        from compact_linux_isa_discovery import bounded_failure_console_lines
        report={"reports":[
            {"target":"busybox","guest_smoke_passed":True,"guest_actual_result":{"status":0}},
            {"target":"binutils","guest_smoke_passed":False,
             "guest_actual_result":{"status":5,"last_rip_hex":"1234","unsupported_syscall_nr":999},
             "candidate":{"image":"main","candidate_bytes_hex":"0f05"}},
        ]}
        lines=bounded_failure_console_lines(report)
        self.assertEqual(len(lines),1)
        self.assertTrue(lines[0].startswith("CLX04_GUEST_FAILURE "))
        import json
        row=json.loads(lines[0].split(" ",1)[1])
        self.assertEqual(row["target"],"binutils")
        self.assertEqual(row["unsupported_syscall_nr"],999)
        self.assertEqual(row["candidate_elf_bytes_hex"],"0f05")
        self.assertFalse(row["opcode_failure_verified"])

    def test_untrusted_names_and_target_collection_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaises(ValueError):
                create_report(root,{"targets":[{"target":"../../etc/passwd","elf":{"sha256":"0"*64}}]})
            with self.assertRaises(ValueError):
                create_report(root,{"targets":[{}]*17})


if __name__=="__main__":
    unittest.main()
