# SPDX-License-Identifier: AGPL-3.0-only
"""ANDNPD 66 0F 55 /r host Linux versus the bounded original Ryzova VM.

Exactly 128 complement-DEST-and-SRC bits; aliases, XMM8+ and aligned m128.
Strict negative misaligned memory and unsupported unprefixed ANDNPS.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/"ryzova/compat/linux"
SOURCES=[CORE/(n+".c") for n in (
    "elf64","namespace","syscall","subset_vm","memory",
    "process","cpu","jobs","jobs_probe"
)]
POSITIVE=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0, XMMWORD PTR [rip + mask_bits]
    movdqu xmm1, XMMWORD PTR [rip + source]
    stc
    andnpd xmm0, xmm1
    movdqu XMMWORD PTR [rip + result0], xmm0
    movdqu xmm2, XMMWORD PTR [rip + source]
    andnpd xmm2, xmm2
    movdqu XMMWORD PTR [rip + result1], xmm2
    movdqu xmm8, XMMWORD PTR [rip + mask_bits]
    andnpd xmm8, xmm1
    movdqu XMMWORD PTR [rip + result2], xmm8
    movdqu xmm3, XMMWORD PTR [rip + mask_bits]
    andnpd xmm3, XMMWORD PTR [rip + source]
    movdqu XMMWORD PTR [rip + result3], xmm3
    pxor xmm4,xmm4
    andnpd xmm4,xmm1
    movdqu XMMWORD PTR [rip + result4], xmm4
    pushfq
    pop rax
    and eax,1
    mov QWORD PTR [rip + carry],rax
    mov eax,1
    mov edi,1
    lea rsi,[rip + result0]
    mov edx,88
    syscall
    mov eax,60
    xor edi,edi
    syscall
.section .data
.balign 16
source: .quad 0xf0f0f0f0f0f0f0f0,0x123456789abcdef0
.balign 16
mask_bits: .quad 0xff00ff00ff00ff00,0xffff0000ffff0000
.section .bss
.balign 16
result0: .zero 16
result1: .zero 16
result2: .zero 16
result3: .zero 16
result4: .zero 16
carry: .zero 8
"""


class AndnpdDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="ryz-andnpd-")
        cls.folder=Path(cls.temp.name)
        cls.runner=cls.folder/"runner"
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                        "-O2",*map(str,SOURCES),"-o",str(cls.runner)],
                       check=True,capture_output=True,timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self,name,asm):
        path=self.folder/(name+".S")
        binary=self.folder/name
        path.write_text(asm)
        subprocess.run(["cc","-nostdlib","-static","-no-pie",
                        str(path),"-o",str(binary)],
                       capture_output=True,check=True,timeout=30)
        return binary

    def test_complement_both_lanes_self_alias_rex_memory_and_carry(self):
        elf=self.build("valid",POSITIVE)
        linux=subprocess.run([str(elf)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(elf)],
                             capture_output=True,timeout=25)
        q=lambda n: n.to_bytes(8,"little")
        before=q(0xf0f0f0f0f0f0f0f0)+q(0x123456789abcdef0)
        bits=q((~0xff00ff00ff00ff00)&0xf0f0f0f0f0f0f0f0)
        bits+=q((~0xffff0000ffff0000)&0x123456789abcdef0)
        expected=bits+bytes(16)+bits+bits+before+q(1)
        self.assertEqual(len(expected),88)
        self.assertEqual(linux.returncode,0,linux.stderr)
        self.assertEqual(linux.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,linux.stdout)
        self.assertIn(b"COMPACT_JOBS_RESULT status=0 exited=1 exit=0",
                      guest.stderr)

    def test_misaligned_memory_fault_matches_native_linux(self):
        asm=r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    movdqu xmm0, XMMWORD PTR [rip + src]
    andnpd xmm0, XMMWORD PTR [rip + misaligned]
    mov eax,60
    xor edi,edi
    syscall
.section .data
.balign 16
src: .quad 0x1234,0x5678
.byte 0x77
misaligned: .quad 0xffff,0xffff
"""
        elf=self.build("misaligned",asm)
        linux=subprocess.run([str(elf)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(elf)],
                             capture_output=True,timeout=20)
        self.assertEqual(linux.returncode,-11,linux.stderr)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=2",guest.stderr)

    def test_unprefixed_andnps_remains_explicitly_unsupported(self):
        asm=r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    .byte 0x0f,0x55,0xc1
    mov eax,60
    xor edi,edi
    syscall
"""
        elf=self.build("andnps-unclaimed",asm)
        linux=subprocess.run([str(elf)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(elf)],
                             capture_output=True,timeout=20)
        self.assertEqual(linux.returncode,0,linux.stderr)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=3",guest.stderr)


if __name__=="__main__":
    unittest.main()
