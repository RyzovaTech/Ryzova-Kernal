#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 5.1 ELF64 load-plan negative tests. No foreign code is executed."""
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
LIB=ROOT/"ryzova/compat/linux"

def fixture(*, e_type=2, machine=62, entry=0x400100, segments=None):
    if segments is None:
        segments=[(1,5,0x100,0x400100,8,32,4096)]
    ident=bytearray(b"\x7fELF"+bytes((2,1,1,0,0))+bytes(7))
    out=bytearray(0x500)
    struct.pack_into("<16sHHIQQQIHHHHHH",out,0,bytes(ident),e_type,machine,1,
                     entry,64,0,0,64,56,len(segments),0,0,0)
    for i,(ptype,flags,offset,va,filesz,memsz,align) in enumerate(segments):
        struct.pack_into("<IIQQQQQQ",out,64+56*i,ptype,flags,offset,va,0,
                         filesz,memsz,align)
        if offset+filesz<=len(out) and filesz>0:
            out[offset:offset+filesz]=bytes([0x90])*filesz
    return out

class ElfFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="ryzova-phase5-")
        cls.directory=Path(cls.temp.name)
        compiler=os.environ.get("PHASE5_CC","cc")
        subprocess.run([compiler,"-std=c11","-O2","-Wall","-Wextra","-Werror",
            "-pedantic","-o",str(cls.directory/"probe"),
            str(LIB/"elf64.c"),str(LIB/"elf64_probe.c")],check=True)
        cls.tool=cls.directory/"probe"
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def probe(self, blob, materialize=False):
        f=self.directory/"fixture.elf"
        f.write_bytes(blob)
        c=[str(self.tool),str(f)]
        if materialize:c.append("--materialize")
        p=subprocess.run(c,capture_output=True,text=True,timeout=5)
        self.assertIn(p.returncode,(0,2),p.stderr)
        return p.returncode,json.loads(p.stdout)
    def assert_invalid(self,blob):
        code,data=self.probe(blob)
        self.assertEqual(code,2,data)
        self.assertEqual(data["status"],"rejected")
    def test_static_elf_load_plan_and_bss(self):
        code,result=self.probe(fixture(),True)
        self.assertEqual(code,0,result)
        self.assertEqual(result["segment_count"],1)
        self.assertEqual(result["entry"],0x400100)
        self.assertEqual(result["mapped_bytes"],4096)
        self.assertTrue(result["materialized"])
    def test_two_nonoverlapping_loads(self):
        two=[(1,5,0x100,0x400100,8,32,4096),
             (1,6,0x200,0x401200,8,32,4096)]
        code,result=self.probe(fixture(segments=two),True)
        self.assertEqual(code,0,result)
        self.assertEqual(result["segment_count"],2)
        self.assertEqual(result["mapped_bytes"],8192)
    def test_real_statically_linked_linux_amd64_elf(self):
        # Validate a genuine Linux-host-built static ET_EXEC, but DO NOT run it.
        source=self.directory/"sample.S"
        source.write_text(".global _start\n_start:\n  mov $60, %rax\n  xor %rdi, %rdi\n  syscall\n")
        binary=self.directory/"sample-linux-static"
        subprocess.run(["cc","-nostdlib","-static","-no-pie","-x","assembler",
                        str(source),"-o",str(binary)],check=True,capture_output=True)
        code,result=self.probe(binary.read_bytes(),True)
        self.assertEqual(code,0,result)
        self.assertGreater(result["segment_count"],0)
    def test_invalid_magic(self):
        x=fixture();x[0]=0;self.assert_invalid(x)
    def test_reject_elf32_and_big_endian(self):
        for index,value in ((4,1),(5,2),(6,0),(7,77),(8,1)):
            x=fixture();x[index]=value
            with self.subTest(index=index):self.assert_invalid(x)
    def test_wrong_machine_and_pie_and_shared(self):
        for cfg in ({"machine":3},{"e_type":3},{"e_type":1}):
            with self.subTest(cfg=cfg):self.assert_invalid(fixture(**cfg))
    def test_wrong_header_sizes(self):
        for off,val in ((52,63),(54,55)):
            x=fixture();struct.pack_into("<H",x,off,val);self.assert_invalid(x)
    def test_outside_program_header_table(self):
        x=fixture();struct.pack_into("<Q",x,32,0x100000)
        self.assert_invalid(x)
        x=fixture();struct.pack_into("<H",x,56,0)
        self.assert_invalid(x)
        x=fixture();struct.pack_into("<H",x,56,33)
        self.assert_invalid(x)
    def test_outside_file_span(self):
        x=fixture()
        struct.pack_into("<Q",x,64+32,0x100000)
        self.assert_invalid(x)
        self.assert_invalid(fixture()[:0x107])
    def test_memsize_less_than_filesize(self):
        x=fixture()
        struct.pack_into("<Q",x,64+40,7)
        self.assert_invalid(x)
    def test_write_executable_segment(self):
        self.assert_invalid(fixture(segments=[(1,7,0x100,0x400100,8,32,4096)]))
    def test_nonaligned_file_and_virtual_address(self):
        self.assert_invalid(fixture(segments=[(1,5,0x100,0x400200,8,32,4096)]))
        self.assert_invalid(fixture(segments=[(1,5,0x100,0x400100,8,32,3)]))
    def test_entry_not_executable_or_bss(self):
        self.assert_invalid(fixture(segments=[(1,4,0x100,0x400100,8,32,4096)]))
        self.assert_invalid(fixture(entry=0x40010c))
    def test_non_user_or_high_address(self):
        self.assert_invalid(fixture(entry=0x1000))
        self.assert_invalid(fixture(segments=[(1,5,0x100,0x7ffffffff100,8,32,4096)],
                                   entry=0x7ffffffff100))
    def test_mapped_memory_budget(self):
        self.assert_invalid(fixture(segments=[(1,5,0x100,0x400100,8,65*1024*1024,4096)]))
    def test_overlapping_mapped_pages(self):
        self.assert_invalid(fixture(segments=[(1,5,0x100,0x400100,8,32,4096),
                                              (1,4,0x180,0x400180,8,32,4096)]))
    def test_reject_dynamic_interpreter_and_tls(self):
        for ptype in (2,3,7):
            x=fixture(segments=[(1,5,0x100,0x400100,8,32,4096),
                                (ptype,4,0,0,0,0,0)])
            with self.subTest(ptype=ptype):self.assert_invalid(x)
    def test_reject_executable_stack(self):
        x=fixture(segments=[(1,5,0x100,0x400100,8,32,4096),
                            (0x6474e551,7,0,0,0,0,16)])
        self.assert_invalid(x)
    def test_no_load_segment(self):
        self.assert_invalid(fixture(segments=[(4,4,0,0,0,0,0)]))
    def test_random_header_mutations_never_crash(self):
        rng=random.Random(314159)
        original=fixture()
        for _ in range(120):
            x=bytearray(original)
            for _ in range(rng.randint(1,7)):
                pos=rng.randrange(0,140)
                x[pos]=rng.randrange(256)
            # A mutation can still form a valid binary: either outcome is fine.
            code,_=self.probe(x)
            self.assertIn(code,(0,2))
if __name__=="__main__":
    unittest.main()
