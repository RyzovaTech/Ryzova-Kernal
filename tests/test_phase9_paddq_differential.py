# SPDX-License-Identifier: AGPL-3.0-only
"""Native Linux vs Ryzova SSE2 PADDQ two-lane wrap and alignment checks.

The native and VM results come from one identical source-built static
AMD64 ELF; native SIGSEGV for unaligned legacy m128 is compared with
the Ryzova guest's bounded map error (no host memory access).
"""
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(x+'.c') for x in
         ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
ASSEMBLY=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0,XMMWORD PTR [rip+initial]
    stc
    paddq xmm0,XMMWORD PTR [rip+other]
    movdqu XMMWORD PTR [rip+output],xmm0
    pushfq
    pop rax
    and eax,1
    mov QWORD PTR [rip+carry_flag],rax
    paddq xmm0,xmm0
    movdqu XMMWORD PTR [rip+output+16],xmm0
    movdqu xmm1,XMMWORD PTR [rip+initial]
    paddq xmm1,xmm0
    movdqu XMMWORD PTR [rip+output+32],xmm1
    mov eax,1
    mov edi,1
    lea rsi,[rip+output]
    mov edx,48
    syscall
    mov eax,1
    mov edi,1
    lea rsi,[rip+carry_flag]
    mov edx,8
    syscall
    mov eax,60
    xor edi,edi
    syscall
.section .rodata
.balign 16
initial: .quad 0xffffffffffffffff,0x7fffffffffffffff
.balign 16
other: .quad 2,1
.section .bss
.balign 16
output: .zero 48
carry_flag: .zero 8
"""


class PaddqDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='clx-paddq-')
        cls.base=Path(cls.tmp.name)
        cls.runner=cls.base/'runner'
        cls.binary=cls.base/'paddq'
        source=cls.base/'paddq.S'
        source.write_text(ASSEMBLY)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       check=True,capture_output=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',str(source),
                        '-o',str(cls.binary)],
                       check=True,capture_output=True,timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_two_independent_u64_lanes_wrapping_alias_and_eflags(self):
        host=subprocess.run([str(self.binary)],capture_output=True,timeout=8)
        guest=subprocess.run([str(self.runner),str(self.binary)],
                             capture_output=True,timeout=25)
        expected=struct.pack('<QQQQQQQ',
            1,0x8000000000000000,2,0,1,0x7fffffffffffffff,1)
        self.assertEqual(host.returncode,0,host.stderr)
        self.assertEqual(host.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,host.stdout)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_unaligned_legacy_m128_denied_like_host_and_mmx_variant_not_claimed(self):
        bad_asm=ASSEMBLY.replace(
            '.balign 16\nother:', '.balign 16\n.byte 0\nother:')
        source=self.base/'unaligned.S'
        binary=self.base/'unaligned'
        source.write_text(bad_asm)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',str(source),
                        '-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        host=subprocess.run([str(binary)],capture_output=True,timeout=8)
        guest=subprocess.run([str(self.runner),str(binary)],
                             capture_output=True,timeout=25)
        self.assertEqual(host.returncode,-11)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',guest.stderr)
        from test_phase9_image_admission import executable
        mmx=self.base/'mmx-unsupported'
        mmx.write_bytes(executable(code=bytes([0x0f,0xd4,0xc1])))
        out=subprocess.run([str(self.runner),str(mmx)],
                           capture_output=True,timeout=10)
        self.assertEqual(out.returncode,2,out.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',out.stderr)


if __name__=='__main__':
    unittest.main()
