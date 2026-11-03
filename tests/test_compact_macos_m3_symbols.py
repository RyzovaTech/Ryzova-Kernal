# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-3B: bounded inert MH_OBJECT nlist_64 and relocations inventory."""
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"


def object_fixture():
    code=b"\x90\xc3"
    strings=b"\0_ryz_entry\0_missing\0"
    sym=0x300
    stroff=0x340
    b=bytearray(1024)
    segment=struct.pack("<II16sQQQQIIII",0x19,152,
                        b"__TEXT".ljust(16,bytes(1)),0,4096,
                        0x200,32,5,5,1,0)
    section=struct.pack("<16s16sQQIIIIIIII",
                        b"__text".ljust(16,bytes(1)),
                        b"__TEXT".ljust(16,bytes(1)),
                        0,len(code),0x200,0,0,0,0,0,0,0)
    symtab=struct.pack("<6I",0x02,24,sym,2,stroff,len(strings))
    commands=segment+section+symtab
    struct.pack_into("<8I",b,0,0xfeedfacf,0x01000007,3,1,
                     2,len(commands),0,0)
    b[32:32+len(commands)]=commands
    b[0x200:0x200+len(code)]=code
    b[sym:sym+16]=struct.pack("<IBBHQ",1,0x0f,1,0,0)
    b[sym+16:sym+32]=struct.pack("<IBBHQ",len(b"\0_ryz_entry\0"),1,0,0,0)
    b[stroff:stroff+len(strings)]=strings
    return b


class Mach3SymbolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.folder=Path(cls.temp.name)
        cls.runner=cls.folder/"m3b-probe"
        cc=os.environ.get("PHASE5_CC","cc")
        flags=[cc,"-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            flags+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        flags += [str(C/"macho_symbol_meta.c"),
                  str(C/"macho_symbol_meta_probe.c"),"-o",str(cls.runner)]
        run=subprocess.run(flags,text=True,capture_output=True,timeout=45)
        if run.returncode:
            raise AssertionError(run.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def scan(self,blob):
        source=self.folder/"sample.macho"
        source.write_bytes(blob)
        return subprocess.run([str(self.runner),str(source)],
                              text=True,capture_output=True,timeout=8)

    def accepted(self,blob):
        r=self.scan(blob)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn("status=0",r.stdout)
        self.assertIn("symbol_resolution=0 native_guest=0",r.stdout)
        return r

    def denied(self,blob):
        r=self.scan(blob)
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertIn("MAC3_SYMBOL status=",r.stdout)
        self.assertIn("symbol_resolution=0 native_guest=0",r.stdout)

    def test_bounded_defined_and_undefined_symbol_records(self):
        r=self.accepted(object_fixture())
        self.assertIn("count=2 defined=1 undefined=1",r.stdout)
        self.assertIn("MAC3_SYMBOL_NAME _ryz_entry 1",r.stdout)
        self.assertIn("MAC3_SYMBOL_NAME _missing 0",r.stdout)

    def test_genuine_clang_darwin_object_with_unresolved_symbol(self):
        asm=self.folder/"darwin-import.s"
        output=self.folder/"darwin-import.o"
        asm.write_text(
            ".text\n.globl _ryz_entry\n_ryz_entry:\n"
            " call _missing_symbol\n ret\n"
        )
        build=subprocess.run([
            "clang","-target","x86_64-apple-macosx13.0",
            "-c",str(asm),"-o",str(output)],
            text=True,capture_output=True,timeout=30
        )
        self.assertEqual(build.returncode,0,build.stderr)
        blob=output.read_bytes()
        self.assertEqual(struct.unpack_from("<I",blob,12)[0],1)
        report=self.accepted(blob)
        self.assertIn("MAC3_SYMBOL_NAME _ryz_entry 1",report.stdout)
        self.assertIn("MAC3_SYMBOL_NAME _missing_symbol 0",report.stdout)
        self.assertIn("symbol_resolution=0",report.stdout)

    def test_wrong_machine_magic_filetype_or_command_shape_rejected(self):
        b=object_fixture()
        for offset,v in ((0,0xfeedface),(4,0x0100000c),(8,8),
                         (12,2),(16,0),(20,0xffffffff),(32+4,9)):
            with self.subTest(offset=offset):
                x=bytearray(b)
                struct.pack_into("<I",x,offset,v)
                self.denied(x)
        self.denied(b[:200])

    def test_symbol_and_string_ranges_are_bounded_and_nonoverlap(self):
        b=object_fixture()
        symtab=32+152
        for offset,value in (
            (symtab+8,0xffffffff),(symtab+12,999),
            (symtab+16,0x300),(symtab+20,99999),
        ):
            with self.subTest(offset=offset):
                x=bytearray(b)
                struct.pack_into("<I",x,offset,value)
                self.denied(x)

    def test_duplicate_symbol_index_name_and_untrusted_type_denied(self):
        b=object_fixture()
        for offset,value,format in (
            (0x300+16,1,"<I"),(0x300,0,"<I"),
            (0x300+4,0xf0,"<B"),(0x300+16+4,0x1f,"<B"),
            (0x300+16+5,1,"<B"),
        ):
            with self.subTest(offset=offset):
                x=bytearray(b)
                struct.pack_into(format,x,offset,value)
                self.denied(x)

    def test_relocation_range_outside_image_denied(self):
        x=object_fixture()
        section=32+72
        struct.pack_into("<I",x,section+56,1022)
        struct.pack_into("<I",x,section+60,1)
        self.denied(x)

    def test_seeded_malformed_inputs_never_crash_host(self):
        rng=random.Random(0x4d41433342)
        good=object_fixture()
        for case in range(128):
            x=bytearray(good)
            for _ in range(1+rng.randrange(5)):
                index=rng.randrange(0,len(x))
                x[index]=rng.randrange(256)
            with self.subTest(case=case):
                r=self.scan(x)
                self.assertIn(r.returncode,(0,2),r.stdout+r.stderr)
                self.assertIn("symbol_resolution=0 native_guest=0",r.stdout)


if __name__=="__main__":
    unittest.main()
