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

def append_command(image, command):
    """Add one bounded load command without changing the synthetic entry data."""
    x=bytearray(image)
    start=32+96
    assert start+len(command)<0x200 and len(command)%8==0
    x[start:start+len(command)]=command
    struct.pack_into("<I",x,16,3)
    struct.pack_into("<I",x,20,96+len(command))
    return x

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
    def test_subtype_must_be_x86_64_all(self):
        for subtype in (0, 8, 0x80000003, 0xffffffff):
            with self.subTest(subtype=subtype):
                x=fixture()
                struct.pack_into("<I",x,8,subtype)
                self.invalid(x)

    def test_segment_must_stay_in_lower_canonical_user_half(self):
        for va,span in ((0x0000800000000000,4096),
                        (0xffff000000000000,4096),
                        (0x00007ffffffff000,8192)):
            with self.subTest(address=hex(va)):
                x=fixture()
                struct.pack_into("<Q",x,56,va)
                struct.pack_into("<Q",x,64,span)
                self.invalid(x)

    def test_exact_uuid_and_duplicate_metadata_commands(self):
        valid=append_command(fixture(),struct.pack("<II16s",0x1b,24,b"\x35"*16))
        self.assertEqual(self.probe(valid).returncode,0)
        self.invalid(append_command(fixture(),struct.pack("<II",0x1b,8)))
        self.invalid(append_command(fixture(),struct.pack("<IIQ",0x1b,16,0)))
        self.invalid(append_command(fixture(),struct.pack("<IIQ",0x80000028,24,0)+b"\x00"*8))

    def test_build_version_requires_macos_and_exact_tool_array(self):
        build=struct.pack("<6I",0x32,24,1,0x000c0000,0x000d0000,0)
        self.assertEqual(self.probe(append_command(fixture(),build)).returncode,0)
        with_tool=struct.pack("<6I2I",0x32,32,1,0x000c0000,0x000d0000,1,1,42)
        self.assertEqual(self.probe(append_command(fixture(),with_tool)).returncode,0)
        mismatched=struct.pack("<6I",0x32,24,1,0x000c0000,0x000d0000,1)
        self.invalid(append_command(fixture(),mismatched))
        wrong_platform=struct.pack("<6I",0x32,24,2,0x000c0000,0x000d0000,0)
        self.invalid(append_command(fixture(),wrong_platform))
        invalid_short=struct.pack("<IIQ",0x32,16,0)
        self.invalid(append_command(fixture(),invalid_short))

    def test_min_macos_version_exact_struct_size(self):
        v=struct.pack("<4I",0x24,16,0x000c0000,0x000d0000)
        self.assertEqual(self.probe(append_command(fixture(),v)).returncode,0)
        self.invalid(append_command(fixture(),struct.pack("<II",0x24,8)))
        self.invalid(append_command(fixture(),struct.pack("<4IQ",0x24,24,0,0,0)))

    def test_segment_command_size_exact_section_geometry(self):
        x=fixture()
        # Move LC_MAIN eight bytes forward and lengthen a sectionless segment.
        x[112:136]=x[104:128]
        struct.pack_into("<I",x,36,80)
        struct.pack_into("<I",x,20,104)
        self.invalid(x)

    def test_reject_ambiguous_executable_file_offset_alias(self):
        x=fixture()
        # Two adjacent executable virtual segments map the same file offsets.
        x[176:200]=x[104:128]
        x[104:176]=x[32:104]
        struct.pack_into("<Q",x,104+24,0x100001000)
        struct.pack_into("<I",x,16,3)
        struct.pack_into("<I",x,20,168)
        self.invalid(x)

    def test_section64_metadata_must_fit_its_segment(self):
        x=fixture()
        # One 80-byte section64 after segment_command_64, before LC_MAIN.
        x[184:208]=x[104:128]
        struct.pack_into("<I",x,36,152)
        struct.pack_into("<I",x,96,1)
        struct.pack_into("<I",x,20,176)
        struct.pack_into("<16s16sQQIIIIIIII",x,104,
                         b"__text".ljust(16,b"\\0"),
                         b"__TEXT".ljust(16,b"\\0"),
                         0x100000200,4,0x200,0,0,0,0,0,0,0)
        self.assertEqual(self.probe(x).returncode,0)
        bad=bytearray(x)
        struct.pack_into("<Q",bad,144,0x3000)  # section size out of segment
        self.invalid(bad)
        bad=bytearray(x)
        struct.pack_into("<I",bad,152,0x2000)  # section file offset out of segment
        self.invalid(bad)
        bad=bytearray(x)
        struct.pack_into("<I",bad,164,1)  # relocations unsupported
        self.invalid(bad)
        bad=bytearray(x)
        struct.pack_into("<I",bad,156,32)  # alignment exponent overflow
        self.invalid(bad)
        bad=bytearray(x)
        bad[120]=ord("Z")  # section segname mismatch
        self.invalid(bad)

    def test_deterministic_mutation_corpus_does_not_crash(self):
        import random
        rng=random.Random(0x4d414330)
        original=fixture()
        for index in range(160):
            x=bytearray(original)
            for _ in range(1+rng.randrange(5)):
                pos=rng.randrange(0,200)
                x[pos]=rng.randrange(256)
            with self.subTest(case=index):
                r=self.probe(x)
                self.assertIn(r.returncode,(0,2),r.stdout+r.stderr)
                self.assertIn("MACHO64 status=",r.stdout)

    def test_reject_too_many_sections(self):
        x=fixture();struct.pack_into("<I",x,96,17);self.invalid(x)
if __name__=="__main__":unittest.main()
