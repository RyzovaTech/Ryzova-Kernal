# SPDX-License-Identifier: AGPL-3.0-only
"""Mach-O x86_64 synthetic metadata checks; never execute input."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"

def fixture():
    b=bytearray(0x1000)
    struct.pack_into("<8I",b,0,0xfeedfacf,0x01000007,3,2,2,96,0,0)
    struct.pack_into("<II16sQQQQIIII",b,32,0x19,72,
                     b"__TEXT".ljust(16,b"\0"),0x100000000,0x1000,
                     0,0x1000,5,5,0,0)
    struct.pack_into("<IIQQ",b,104,0x80000028,24,0x200,0)
    b[0x200:0x204]=b"\x90\x90\xc3\x90"
    return b

class MachoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.directory=Path(cls.temp.name)
        cc=os.environ.get("PHASE5_CC","cc")
        flags=["-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            flags+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        p=subprocess.run([cc,*flags,str(C/"macho64.c"),str(C/"macho64_probe.c"),
                         "-o",str(cls.directory/"probe")],capture_output=True,text=True)
        if p.returncode:raise AssertionError(p.stderr)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def probe(self,b):
        file=self.directory/"test.macho"
        file.write_bytes(b)
        return subprocess.run([str(self.directory/"probe"),str(file)],capture_output=True,text=True,timeout=5)
    def invalid(self,b):
        r=self.probe(b)
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
    def test_valid_metadata(self):
        r=self.probe(fixture())
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn("segments=1",r.stdout)
        self.assertIn("entry=4294967808",r.stdout)
        self.assertIn("(not executed)",r.stdout)
    def test_wrong_magic_or_cputype(self):
        x=fixture();x[0]=0;self.invalid(x)
        x=fixture();struct.pack_into("<I",x,4,0x0100000c);self.invalid(x)
    def test_pie_and_filetype(self):
        x=fixture();struct.pack_into("<I",x,24,0x200000);self.invalid(x)
        x=fixture();struct.pack_into("<I",x,12,6);self.invalid(x)
    def test_bad_command_length_and_overflow(self):
        x=fixture();struct.pack_into("<I",x,20,0xffffffff);self.invalid(x)
        x=fixture();struct.pack_into("<I",x,36,0xffffffff);self.invalid(x)
        x=fixture();struct.pack_into("<I",x,16,0);self.invalid(x)
    def test_reject_dylib_and_dyld_commands(self):
        for cmd in (0xc,0xe,0x80000022,0x1d,0x5):
            with self.subTest(cmd=cmd):
                x=fixture();struct.pack_into("<I",x,104,cmd);self.invalid(x)
    def test_writable_executable_segment(self):
        x=fixture();struct.pack_into("<I",x,88,7);self.invalid(x)
        x=fixture();struct.pack_into("<I",x,92,7);self.invalid(x)
    def test_bad_segment_range_or_alignment(self):
        x=fixture();struct.pack_into("<Q",x,72,0xffffffffffffffff);self.invalid(x)
        x=fixture();struct.pack_into("<Q",x,56,0x100000001);self.invalid(x)
        self.invalid(fixture()[:0x800])
    def test_missing_main(self):
        x=fixture();struct.pack_into("<I",x,104,0x1b);self.invalid(x)
    def test_main_outside_file_backed_exec(self):
        x=fixture();struct.pack_into("<Q",x,112,0x4000);self.invalid(x)
    def test_reject_too_many_sections(self):
        x=fixture();struct.pack_into("<I",x,96,17);self.invalid(x)
if __name__=="__main__":unittest.main()
