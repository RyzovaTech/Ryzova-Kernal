# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded PE32+ AMD64 format checks: image is NEVER executed."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
PE=ROOT/"ryzova/compat/windows"

def fixture():
    p=bytearray(0x400)
    p[0:2]=b"MZ"
    struct.pack_into("<I",p,0x3c,0x80)
    p[0x80:0x84]=b"PE\0\0"
    struct.pack_into("<HHIIIHH",p,0x84,0x8664,1,0,0,0,240,0x22)
    opt=0x98
    struct.pack_into("<H",p,opt,0x20b)
    struct.pack_into("<I",p,opt+16,0x1000)
    struct.pack_into("<Q",p,opt+24,0x140000000)
    struct.pack_into("<I",p,opt+32,4096)
    struct.pack_into("<I",p,opt+36,512)
    struct.pack_into("<I",p,opt+56,0x2000)
    struct.pack_into("<I",p,opt+60,512)
    struct.pack_into("<I",p,opt+108,16)
    sec=opt+240
    p[sec:sec+8]=b".text\0\0\0"
    struct.pack_into("<IIII",p,sec+8,0x20,0x1000,0x200,0x200)
    struct.pack_into("<I",p,sec+36,0x60000020)
    p[0x200:0x204]=b"\x90\x90\xc3\x00"
    return p

class TestPE64(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cc=os.environ.get("PHASE5_CC","cc")
        args=[cc,"-std=c11","-O2","-Wall","-Wextra","-Werror","-pedantic",
              str(PE/"pe64.c"),str(PE/"pe64_probe.c"),"-o",str(cls.root/"probe")]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            args[1:1]=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        z=subprocess.run(args,capture_output=True,text=True)
        if z.returncode:raise AssertionError(z.stderr)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def run_pe(self,buf):
        path=self.root/"sample.exe"
        path.write_bytes(buf)
        return subprocess.run([str(self.root/"probe"),str(path)],
            capture_output=True,text=True,timeout=5)
    def invalid(self,blob):
        p=self.run_pe(blob)
        self.assertEqual(p.returncode,2,p.stdout+p.stderr)
    def test_valid_pe64_metadata_only(self):
        p=self.run_pe(fixture())
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertIn("status=0 sections=1 entry=4096",p.stdout)
        self.assertIn("not executed",p.stdout)
    def test_bad_dos_header_and_pe_signature(self):
        a=fixture();a[0]=0;self.invalid(a)
        a=fixture();a[0x80]=0;self.invalid(a)
    def test_bad_machine_or_pe32(self):
        a=fixture();struct.pack_into("<H",a,0x84,0x14c);self.invalid(a)
        a=fixture();struct.pack_into("<H",a,0x98,0x10b);self.invalid(a)
    def test_invalid_offsets_and_truncated(self):
        a=fixture();struct.pack_into("<I",a,0x3c,0xffffffff);self.invalid(a)
        self.invalid(fixture()[:0x200])
    def test_reject_writable_executable_section(self):
        a=fixture();struct.pack_into("<I",a,0x188+36,0xe0000020);self.invalid(a)
    def test_reject_dll(self):
        a=fixture();struct.pack_into("<H",a,0x96,0x2022);self.invalid(a)
    def test_reject_imports_and_relocations_and_tls_and_clr(self):
        for idx in (1,3,5,9,14):
            a=fixture();struct.pack_into("<II",a,0x98+112+8*idx,0x1000,8)
            with self.subTest(dir=idx):self.invalid(a)
    def test_entrypoint_outside_text(self):
        a=fixture();struct.pack_into("<I",a,0x98+16,0x1500);self.invalid(a)
    def test_unsafe_image_size(self):
        a=fixture();struct.pack_into("<I",a,0x98+56,0xffffffff);self.invalid(a)
    def test_section_raw_data_outside_file(self):
        a=fixture();struct.pack_into("<I",a,0x188+20,0xffffff00);self.invalid(a)
if __name__=="__main__":
    unittest.main()
