# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-3C source-built bounded x86_64 Mach-O object linker tests.

Tests *real* Clang-generated MH_OBJECT branch relocations resolved by the
original Ryzova linker, then executed by the host-only Ryzova interpreter.
No dyld, libSystem, native Ryzova guest or Apple linked app is involved.
"""
import os
import random
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"
ENTRY=r"""
.text
.globl _ryz_entry
_ryz_entry:
    call _ryz_helper
    ret
"""
HELPER=r"""
.text
.globl _ryz_helper
_ryz_helper:
    movl $42, %eax
    ret
"""


class Mac3cStaticObjectLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.folder=Path(cls.tmp.name)
        cls.runner=cls.folder/"mac3c_link_probe"
        cc=os.environ.get("PHASE5_CC","cc")
        cmd=[cc,"-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            cmd+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        cmd += [str(C/file) for file in
                ("macho64.c","macho_vm.c","macho_static_link.c",
                 "macho_static_link_probe.c")]
        cmd+=["-o",str(cls.runner)]
        build=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             text=True,timeout=50)
        if build.returncode:
            raise AssertionError(build.stderr)
        cls.src1=cls.folder/"entry.s"
        cls.src2=cls.folder/"helper.s"
        cls.obj1=cls.folder/"entry.o"
        cls.obj2=cls.folder/"helper.o"
        cls.build_clang(ENTRY,cls.src1,cls.obj1)
        cls.build_clang(HELPER,cls.src2,cls.obj2)

    @classmethod
    def build_clang(cls,code,source,output):
        source.write_text(code)
        build=subprocess.run(["clang","-target","x86_64-apple-macosx13.0",
                              "-c",str(source),"-o",str(output)],
                             capture_output=True,text=True,timeout=30)
        if build.returncode:
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def launch(self,first,second):
        p=self.folder/"changed-first.o"
        q=self.folder/"changed-second.o"
        p.write_bytes(first)
        q.write_bytes(second)
        return subprocess.run([str(self.runner),str(p),str(q)],
                              capture_output=True,text=True,timeout=12)

    def allowed(self,first=None,second=None,expected_relocs=1):
        first=first if first is not None else self.obj1.read_bytes()
        second=second if second is not None else self.obj2.read_bytes()
        p=self.launch(first,second)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertIn("MAC3C_LINK status=0",p.stdout)
        self.assertIn(f"branch_relocations={expected_relocs}",p.stdout)
        self.assertIn(f"resolved_externals={expected_relocs}",p.stdout)
        self.assertIn("vm_status=0 eax=42 returned=1",p.stdout)
        self.assertIn("native_guest=0 dyld=0 libsystem=0 host_forwarding=0",p.stdout)
        return p

    def denied(self,first,second):
        p=self.launch(first,second)
        self.assertEqual(p.returncode,2,p.stdout+p.stderr)
        self.assertIn("MAC3C_LINK status=",p.stdout)
        self.assertIn("native_guest=0 dyld=0 libsystem=0 host_forwarding=0",p.stdout)
        self.assertNotIn("MAC3C_LINK status=0 objects=2",p.stdout)

    def test_real_clang_darwin_branch_relocation_executes_42(self):
        first=self.obj1.read_bytes()
        second=self.obj2.read_bytes()
        self.assertEqual(struct.unpack_from("<I",first,12)[0],1)
        self.assertEqual(struct.unpack_from("<I",second,12)[0],1)
        self.allowed(first,second)

    def test_two_distinct_relocations_resolve_same_symbol(self):
        first=self.obj1.read_bytes()
        extra=r"""
.text
.globl _ryz_entry
_ryz_entry:
    call _ryz_helper
    call _ryz_helper
    ret
"""
        src=self.folder/"double.s"
        obj=self.folder/"double.o"
        self.build_clang(extra,src,obj)
        self.allowed(obj.read_bytes(),self.obj2.read_bytes(),expected_relocs=2)

    def test_unresolved_external_symbol_fails_closed(self):
        first=self.obj1.read_bytes()
        other=r"""
.text
.globl _ryz_other
_ryz_other:
    movl $42, %eax
    ret
"""
        source=self.folder/"other.s"
        target=self.folder/"other.o"
        self.build_clang(other,source,target)
        self.denied(first,target.read_bytes())

    def test_entry_must_be_in_first_object(self):
        self.denied(self.obj2.read_bytes(),self.obj1.read_bytes())

    def test_wrong_architecture_and_filetype_not_admitted(self):
        first=self.obj1.read_bytes()
        second=self.obj2.read_bytes()
        for offset,value in ((0,0xfeedface),(4,0x0100000c),(8,8),
                             (12,2),(24,0xffffffff)):
            with self.subTest(offset=offset):
                bad=bytearray(first)
                struct.pack_into("<I",bad,offset,value)
                self.denied(bad,second)

    def test_corrupt_external_branch_type_pcrel_length_and_symbol(self):
        first=self.obj1.read_bytes()
        second=self.obj2.read_bytes()
        # Use a section header, never a guessed relocation offset.
        section=32+72
        reloc=struct.unpack_from("<I",first,section+56)[0]
        original=struct.unpack_from("<I",first,reloc+4)[0]
        for info in (
            original&~(1<<24),        # no PC-relative relocation
            original&~(1<<27),        # non-external
            original&~(3<<25),        # wrong relocation width
            (original&0x0fffffff)|(3<<28), # GOT load, not branch
            (original&0xff000000)|0xffffff, # nonexistent symbol
        ):
            with self.subTest(info=hex(info)):
                bad=bytearray(first)
                struct.pack_into("<I",bad,reloc+4,info)
                self.denied(bad,second)

    def test_reject_overlapped_text_relocation_and_symbol_table_regions(self):
        first=self.obj1.read_bytes()
        second=self.obj2.read_bytes()
        section=32+72
        code_off=struct.unpack_from("<I",first,section+48)[0]
        # Executable section cannot alias the Mach-O command header.
        wrong=bytearray(first)
        struct.pack_into("<I",wrong,section+48,32)
        self.denied(wrong,second)
        # Relocation table cannot masquerade as code bytes.
        wrong=bytearray(first)
        struct.pack_into("<I",wrong,section+56,code_off)
        self.denied(wrong,second)
        # Relocation table cannot masquerade as symbol entries.
        wrong=bytearray(first)
        symtab=32+152+24
        symoff=struct.unpack_from("<I",wrong,symtab+8)[0]
        struct.pack_into("<I",wrong,section+56,symoff)
        self.denied(wrong,second)

    def test_reject_nonzero_branch_addend_and_invalid_reloc_offset(self):
        first=self.obj1.read_bytes()
        second=self.obj2.read_bytes()
        section=32+72
        bad=bytearray(first)
        offset=struct.unpack_from("<I",first,section+48)[0]
        bad[offset+1:offset+5]=b"\x01\x00\x00\x00"
        self.denied(bad,second)
        bad=bytearray(first)
        reloc=struct.unpack_from("<I",first,section+56)[0]
        struct.pack_into("<I",bad,reloc,0xffffffff)
        self.denied(bad,second)

    def test_reject_oversize_or_truncated_object(self):
        self.denied(self.obj1.read_bytes()[:80],self.obj2.read_bytes())
        # File-oriented probe rejects oversize input *before* entering
        # the linker; its documented CLI error is 65, not link status 2.
        oversize=self.folder/"oversize.o"
        oversize.write_bytes(self.obj1.read_bytes()+bytes(65537))
        result=subprocess.run([str(self.runner),str(oversize),str(self.obj2)],
                              capture_output=True,text=True,timeout=8)
        self.assertEqual(result.returncode,65,result.stdout+result.stderr)

    def test_seeded_corrupt_cross_object_metadata_never_crashes_host(self):
        rng=random.Random(0x4d41433343)
        original1=self.obj1.read_bytes()
        original2=self.obj2.read_bytes()
        for iteration in range(128):
            first=bytearray(original1)
            second=bytearray(original2)
            target=first if iteration%2==0 else second
            for _ in range(1+rng.randrange(5)):
                index=rng.randrange(len(target))
                target[index]=rng.randrange(256)
            with self.subTest(case=iteration):
                output=self.launch(first,second)
                self.assertIn(output.returncode,(0,2),output.stdout+output.stderr)
                self.assertIn("MAC3C_LINK status=",output.stdout)
                self.assertIn("native_guest=0 dyld=0 libsystem=0",output.stdout)

    def test_duplicate_definition_is_rejected_even_when_one_is_unused(self):
        # No ambiguous global _ryz_helper definition is allowed across the
        # two objects, even though one object owns the test entrypoint.
        entry=r"""
.text
.globl _ryz_entry
.globl _ryz_helper
_ryz_entry:
    call _ryz_helper
    ret
_ryz_helper:
    movl $1, %eax
    ret
"""
        p=self.folder/"duplicate.s"
        obj=self.folder/"duplicate.o"
        self.build_clang(entry,p,obj)
        self.denied(obj.read_bytes(),self.obj2.read_bytes())

    def test_linker_does_not_forward_syscall_or_load_dylib(self):
        first=r"""
.text
.globl _ryz_entry
_ryz_entry:
    call _ryz_helper
    ret
"""
        second=r"""
.text
.globl _ryz_helper
_ryz_helper:
    movl $0x2000004,%eax
    syscall
    ret
"""
        p=self.folder/"syscall.o"
        src=self.folder/"syscall.s"
        self.build_clang(first,self.src1,self.obj1)
        self.build_clang(second,src,p)
        result=self.launch(self.obj1.read_bytes(),p.read_bytes())
        self.assertEqual(result.returncode,2)
        self.assertIn("MAC3C_LINK status=0",result.stdout)
        self.assertIn("vm_status=5",result.stdout)
        self.assertIn("host_forwarding=0",result.stdout)
        self.assertIn("dyld=0 libsystem=0",result.stdout)

if __name__=="__main__":
    unittest.main()
