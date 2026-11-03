# SPDX-License-Identifier: AGPL-3.0-only
"""Differential SSE2 PCMPEQD regression on host x86_64 and Ryzova VM.

The exact same source-built AMD64 ELF runs on native Linux and the bounded
Ryzova interpreter; byte-for-byte output and flags must match. This is a
finite ISA subset test, not a Python workflow or complete AMD64-ABI gate.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(n+'.c') for n in (
    'elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe'
)]
ASSEMBLY=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0, XMMWORD PTR [rip + left]
    movdqu xmm1, XMMWORD PTR [rip + right]
    stc
    pcmpeqd xmm0, xmm1
    movdqu XMMWORD PTR [rip + out0], xmm0
    pushfq
    pop rax
    and eax, 1
    mov QWORD PTR [rip + carry], rax
    movdqu xmm2, XMMWORD PTR [rip + left]
    pcmpeqd xmm2, XMMWORD PTR [rip + right]
    movdqu XMMWORD PTR [rip + out1], xmm2
    pcmpeqd xmm3, xmm3
    movdqu XMMWORD PTR [rip + out2], xmm3
    movdqu xmm8, XMMWORD PTR [rip + left]
    pcmpeqd xmm8, xmm1
    movdqu XMMWORD PTR [rip + out3], xmm8
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + out0]
    mov edx, 64
    syscall
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + carry]
    mov edx, 8
    syscall
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
left: .long 0x11111111, 0x22222222, 0x33333333, 0x44444444
.balign 16
right: .long 0x11111111, 0x99999999, 0x33333333, 0
.section .bss
.balign 16
out0: .zero 16
out1: .zero 16
out2: .zero 16
out3: .zero 16
carry: .zero 8
"""


class PcmpeqdDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='clx-pcmpeqd-')
        cls.root=Path(cls.temp.name)
        cls.runner=cls.root/'runner'
        cls.binary=cls.root/'pcmpeqd'
        source=cls.root/'pcmpeqd.S'
        source.write_text(ASSEMBLY)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       capture_output=True,check=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),
                        '-o',str(cls.binary)],
                       capture_output=True,check=True,timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_equal_unequal_memory_self_alias_rex_and_eflags(self):
        native=subprocess.run([str(self.binary)],capture_output=True,timeout=8)
        guest=subprocess.run([str(self.runner),str(self.binary)],
                             capture_output=True,timeout=25)
        mask=b'\xff'*4+b'\x00'*4+b'\xff'*4+b'\x00'*4
        expected=mask+mask+b'\xff'*16+mask+(1).to_bytes(8,'little')
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(native.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_misaligned_m128_denied_like_linux_and_mmx_not_claimed(self):
        badasm=ASSEMBLY.replace('.balign 16\nright:', '.balign 16\n.byte 11\nright:')
        source=self.root/'unaligned.S'
        binary=self.root/'unaligned'
        source.write_text(badasm)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',str(source),
                        '-o',str(binary)],capture_output=True,check=True,timeout=30)
        host=subprocess.run([str(binary)],capture_output=True,timeout=8)
        guest=subprocess.run([str(self.runner),str(binary)],
                             capture_output=True,timeout=25)
        self.assertEqual(host.returncode,-11)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',guest.stderr)
        from test_phase9_image_admission import executable
        mmx=self.root/'mmx-unsupported'
        mmx.write_bytes(executable(code=bytes([0x0f,0x76,0xc1])))
        r=subprocess.run([str(self.runner),str(mmx)],
                         capture_output=True,timeout=10)
        self.assertEqual(r.returncode,2,r.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',r.stderr)


if __name__=='__main__':
    unittest.main()
