# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed W7 userspace ARM64-QEMU acceptance parser unit checks.

Actual machine-code execution is required by the separate dedicated CI job.
"""
import struct
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_w7_arm64_qemu_user import (
    arm64_linux_elf, pe_entry_raw, mutate, parse_result, sha256
)


class W7QemuUserEvidenceTests(unittest.TestCase):
    def make_pe(self):
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
        sec=0x80+24+0xf0
        struct.pack_into("<I",data,sec+12,0x1000)
        struct.pack_into("<I",data,sec+16,0x200)
        struct.pack_into("<I",data,sec+20,0x200)
        struct.pack_into("<I",data,sec+36,0x60000020)
        struct.pack_into("<I",data,0x200,0xd65f03c0)
        return bytes(data)

    def test_real_arm64_elf_header_required(self):
        raw=bytearray(64)
        raw[:6]=b"\x7fELF\x02\x01"
        struct.pack_into("<H",raw,16,2)
        struct.pack_into("<H",raw,18,183)
        self.assertEqual(arm64_linux_elf(bytes(raw)),sha256(bytes(raw)))
        struct.pack_into("<H",raw,18,62)
        with self.assertRaises(ValueError):
            arm64_linux_elf(bytes(raw))
        with self.assertRaises(ValueError):
            arm64_linux_elf(b"MZ"+bytes(100))

    def test_original_pe_entry_and_negative_mutations_are_bounded(self):
        source=self.make_pe()
        self.assertEqual(pe_entry_raw(source),0x200)
        expected={
            "arm64ec-denied":(0x84,(0xa641).to_bytes(2,"little")),
            "svc-denied":(0x200,(0xd4000001).to_bytes(4,"little")),
            "illegal-denied":(0x200,b"\xff"*4),
            "step-limit":(0x200,(0x14000000).to_bytes(4,"little")),
            "imports-denied":(0x98+112+8,(0x1000).to_bytes(4,"little")),
        }
        for name,(offset,words) in expected.items():
            with self.subTest(case=name):
                result=mutate(source,name)
                self.assertEqual(result[offset:offset+len(words)],words)
                self.assertEqual(len(result),len(source))
                self.assertNotEqual(sha256(result),sha256(source))
        with self.assertRaises(ValueError):
            mutate(source,"unknown-syscall")
        with self.assertRaises(ValueError):
            pe_entry_raw(source[:64])
        with self.assertRaises(ValueError):
            pe_entry_raw(mutate(source,"arm64ec-denied"))
        noexec=bytearray(source)
        sec=0x80+24+0xf0
        struct.pack_into("<I",noexec,sec+36,0x40000040)
        with self.assertRaises(ValueError):
            pe_entry_raw(bytes(noexec))

    def test_receipt_parser_rejects_fake_exit_or_wrong_step_limit(self):
        def result(status=0,exit_code=37,steps=5):
            return (f"CW_ARM64_RESULT status={status} exit={exit_code} "
                    f"steps={steps} pc=1000 insn=d65f03c0\n").encode("ascii")
        self.assertEqual(parse_result(result(),0,b"")["exit_code"],37)
        self.assertEqual(parse_result(result(2,0),3,b"")["status"],2)
        rejected=(
            (result(),1,b""),
            (result(4,0,4097),5,b""),
            (result(5,0),6,b""),
            (result(),0,b"unexpected host output"),
            (b"native_windows_qualified=true",0,b""),
            (result()+b"garbage",0,b""),
            (b"A"*2048,0,b""),
        )
        for data,code,stderr in rejected:
            with self.subTest(code=code,size=len(data)):
                with self.assertRaises(ValueError):
                    parse_result(data,code,stderr)


if __name__=="__main__":
    unittest.main()
