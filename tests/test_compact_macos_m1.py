# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-1: bounded real AMD64 instruction interpretation from synthetic Mach-O.

Tests exercise Ryzova's *host* virtual CPU. They do not claim dyld, Darwin
syscalls, native Ryzova guest execution, or general macOS application support.
"""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"
BASE=0x100000000
ENTRY=0x200


def signed_disp(target, after):
    return struct.pack("<i",target-after)


def sample(code, *, data=False, data_file_bytes=4096):
    if not 1<=len(code)<=256:
        raise ValueError("bounded synthetic code required")
    ncmd=3 if data else 2
    commands=168 if data else 96
    b=bytearray(8192 if data else 4096)
    struct.pack_into("<8I",b,0,0xfeedfacf,0x01000007,3,2,ncmd,commands,0,0)
    struct.pack_into("<II16sQQQQIIII",b,32,
                     0x19,72,b"__TEXT".ljust(16,b"\0"),
                     BASE,4096,0,4096,5,5,0,0)
    main=104
    if data:
        if not 0<=data_file_bytes<=4096:
            raise ValueError("invalid data bytes")
        struct.pack_into("<II16sQQQQIIII",b,104,
                         0x19,72,b"__DATA".ljust(16,b"\0"),
                         BASE+4096,4096,4096,data_file_bytes,3,3,0,0)
        main=176
    struct.pack_into("<IIQQ",b,main,0x80000028,24,ENTRY,0)
    b[ENTRY:ENTRY+len(code)]=code
    if data and data_file_bytes>=0x104:
        struct.pack_into("<I",b,0x1100,40)
    return b


class MachoMac1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.runner=cls.root/"mac1-host-only-probe"
        cc=os.environ.get("PHASE5_CC","cc")
        args=[cc,"-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            args+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        args += [str(C/"macho64.c"),str(C/"macho_vm.c"),
                 str(C/"macho_vm_probe.c"),"-o",str(cls.runner)]
        compile=subprocess.run(args,text=True,capture_output=True,timeout=45)
        if compile.returncode:
            raise AssertionError(compile.stderr)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def execute(self,image,steps=None):
        file=self.root/"sample.macho"
        file.write_bytes(image)
        cmd=[str(self.runner),str(file)]
        if steps is not None:
            cmd.append(str(steps))
        return subprocess.run(cmd,text=True,capture_output=True,timeout=6)

    def check(self,image,status,*,eax=None,steps=None):
        r=self.execute(image,steps)
        self.assertEqual(r.returncode,0 if status==0 else 2,r.stdout+r.stderr)
        self.assertIn("MAC1_VM status="+str(status),r.stdout)
        self.assertIn("host_interpreter=1 native_guest=0 darwin_syscalls=0",r.stdout)
        if eax is not None:
            self.assertIn("eax="+str(eax),r.stdout)
        return r

    def test_integer_entry_produces_42_without_host_exec(self):
        # x86_64: mov eax,40; add eax,2; ret
        code=bytes([0xb8,40,0,0,0,0x83,0xc0,2,0xc3])
        r=self.check(sample(code),0,eax=42)
        self.assertIn("test_return=1",r.stdout)
        self.assertIn("steps=3",r.stdout)

    def test_unsigned_wrap_and_explicit_integer_operations(self):
        code=bytes([0xb8,255,255,255,255,0x83,0xc0,2,0xc3])
        self.check(sample(code),0,eax=1)
        self.check(sample(bytes([0xb8,12,0,0,0,0x31,0xc0,0xff,0xc0,0xc3])),0,eax=1)
        self.check(sample(bytes([0xb8,42,0,0,0,0x05,2,0,0,0,0xc3])),0,eax=44)

    def test_zero_filled_mapped_region_and_read_access(self):
        # mov eax,[rip+disp32] from the zero-filled __DATA region
        code=b"\x8b\x05"+signed_disp(0x1200,ENTRY+6)+b"\x83\xc0\x2a\xc3"
        self.check(sample(code,data=True,data_file_bytes=0x100),0,eax=42)

    def test_rip_relative_data_read_write_with_bounded_permissions(self):
        read=b"\x8b\x05"+signed_disp(0x1100,ENTRY+6)
        add=b"\x83\xc0\x02"
        store_at=ENTRY+len(read)+len(add)
        store=b"\x89\x05"+signed_disp(0x1104,store_at+6)
        reload_at=store_at+len(store)
        reload=b"\x8b\x05"+signed_disp(0x1104,reload_at+6)
        self.check(sample(read+add+store+reload+b"\xc3",data=True),0,eax=42)

    def test_code_write_is_denied_even_on_host(self):
        code=b"\xb8\x2a\x00\x00\x00"
        code+=b"\x89\x05"+signed_disp(0x250,ENTRY+len(code)+6)
        code+=b"\xc3"
        self.check(sample(code),8)

    def test_execute_from_non_executable_data_denied(self):
        code=b"\xe9"+signed_disp(0x1100,ENTRY+5)
        self.check(sample(code,data=True),3)

    def test_guest_syscall_explicitly_denied(self):
        self.check(sample(b"\x0f\x05\xc3"),5)

    def test_unknown_and_truncated_instructions_denied(self):
        self.check(sample(b"\xf4\xc3"),4)
        self.check(sample(b"\x83\xd0\x01\xc3"),4)
        # A partial MOV immediate cannot fetch its operand from zero-filled
        # memory beyond the executable segment's file-backed bytes.
        truncated=sample(b"\xb8\xc3")
        struct.pack_into("<Q",truncated,32+48,ENTRY+2)
        self.check(truncated,3)

    def test_infinite_jmp_cannot_exhaust_host_cpu(self):
        r=self.check(sample(b"\xeb\xfe"),6,steps=32)
        self.assertIn("steps=32",r.stdout)

    def test_guest_policy_denies_invalid_budget(self):
        x=sample(b"\xc3")
        for value in (0,-1,4097,99999999,"not-a-number"):
            with self.subTest(value=value):
                r=self.execute(x,value)
                self.assertEqual(r.returncode,64)

    def test_parser_denies_dynamic_commands_pie_and_writable_executable(self):
        x=sample(b"\xc3")
        for offset,value in ((24,0x200000),(4,0x0100000c),
                             (88,7),(92,7)):
            with self.subTest(offset=offset):
                invalid=bytearray(x)
                struct.pack_into("<I",invalid,offset,value)
                self.check(invalid,1)

    def test_memory_aggregate_denied_independent_of_sparse_elf_size(self):
        x=sample(b"\xc3",data=True)
        # 5MiB each, nonoverlapping, still valid by Mach-O metadata policy.
        struct.pack_into("<Q",x,32+32,5*1024*1024)
        struct.pack_into("<Q",x,104+24,BASE+6*1024*1024)
        struct.pack_into("<Q",x,104+32,5*1024*1024)
        self.check(x,2)

    def test_reject_forged_host_pointer_ranges_and_oversize_input(self):
        x=sample(b"\xc3")
        struct.pack_into("<Q",x,32+24,0x0000800000000000)
        self.check(x,1)
        self.check(b"not a Mach-O"+bytes(32),1)
        too_big=sample(b"\xc3")
        too_big.extend(bytes(4*1024*1024+1-len(too_big)))
        file=self.root/"too-big.macho"
        file.write_bytes(too_big)
        r=subprocess.run([str(self.runner),str(file)],text=True,capture_output=True)
        self.assertEqual(r.returncode,65)


if __name__=="__main__":
    unittest.main()
