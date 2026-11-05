# SPDX-License-Identifier: AGPL-3.0-only
"""Same static AMD64 ELF on native Linux and original Ryzova interpreter.

F2 0F 5D MINSD: exact binary64 lane bytes, qNaN source selection,
source-selected +/- zero, unaligned m64, REX XMM8, register aliases,
upper-64 and EFLAGS preservation. This is not full MXCSR qualification.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "ryzova/compat/linux"
SOURCES = [CORE / (name + ".c") for name in (
    "elf64", "namespace", "syscall", "subset_vm", "memory",
    "process", "cpu", "jobs", "jobs_probe"
)]
ASM = r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
  stc
  movdqu xmm0, XMMWORD PTR [rip+dst_pos]
  movdqu xmm1, XMMWORD PTR [rip+src_small]
  minsd xmm0,xmm1
  movdqu XMMWORD PTR [rip+out0],xmm0
  movdqu xmm0, XMMWORD PTR [rip+dst_neg]
  movdqu xmm1, XMMWORD PTR [rip+src_two]
  minsd xmm0,xmm1
  movdqu XMMWORD PTR [rip+out1],xmm0
  movdqu xmm0, XMMWORD PTR [rip+dst_pluszero]
  movdqu xmm1, XMMWORD PTR [rip+src_minuszero]
  minsd xmm0,xmm1
  movdqu XMMWORD PTR [rip+out2],xmm0
  movdqu xmm0, XMMWORD PTR [rip+dst_minuszero]
  movdqu xmm1, XMMWORD PTR [rip+src_pluszero]
  minsd xmm0,xmm1
  movdqu XMMWORD PTR [rip+out3],xmm0
  movdqu xmm0, XMMWORD PTR [rip+dst_nan]
  movdqu xmm1, XMMWORD PTR [rip+src_small]
  minsd xmm0,xmm1
  movdqu XMMWORD PTR [rip+out4],xmm0
  movdqu xmm0, XMMWORD PTR [rip+dst_pos]
  movdqu xmm1, XMMWORD PTR [rip+src_nan]
  minsd xmm0,xmm1
  movdqu XMMWORD PTR [rip+out5],xmm0
  movdqu xmm0, XMMWORD PTR [rip+dst_pos]
  minsd xmm0,QWORD PTR [rip+memory_unaligned]
  movdqu XMMWORD PTR [rip+out6],xmm0
  movdqu xmm8, XMMWORD PTR [rip+dst_pos]
  movdqu xmm9, XMMWORD PTR [rip+src_two]
  minsd xmm8,xmm9
  movdqu XMMWORD PTR [rip+out7],xmm8
  movdqu xmm3, XMMWORD PTR [rip+dst_nan]
  minsd xmm3,xmm3
  movdqu XMMWORD PTR [rip+out8],xmm3
  pushfq
  pop rax
  and eax, 1
  mov QWORD PTR [rip+carry],rax
  mov eax,1
  mov edi,1
  lea rsi,[rip+out0]
  mov edx,152
  syscall
  mov eax,60
  xor edi,edi
  syscall
.section .data
.balign 16
dst_pos:       .quad 0x4016000000000000,0x1111111111111111
dst_neg:       .quad 0xc01c000000000000,0x1111111111111111
dst_pluszero:  .quad 0x0000000000000000,0x1111111111111111
dst_minuszero: .quad 0x8000000000000000,0x1111111111111111
dst_nan:       .quad 0x7ff800000000005a,0x1111111111111111
src_small:     .quad 0x400a000000000000,0x2222222222222222
src_two:       .quad 0x4000000000000000,0x2222222222222222
src_minuszero: .quad 0x8000000000000000,0x2222222222222222
src_pluszero:  .quad 0x0000000000000000,0x2222222222222222
src_nan:       .quad 0x7ff8000000000071,0x2222222222222222
.byte 0xab
memory_unaligned: .quad 0x400a000000000000
.section .bss
.balign 16
out0: .zero 16
out1: .zero 16
out2: .zero 16
out3: .zero 16
out4: .zero 16
out5: .zero 16
out6: .zero 16
out7: .zero 16
out8: .zero 16
carry: .zero 8
"""


class MinsdDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ryz-minsd-")
        cls.folder = Path(cls.temp.name)
        cls.runner = cls.folder / "runner"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-O2", *map(str, SOURCES), "-o", str(cls.runner)],
                       check=True, capture_output=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self, name, source):
        path = self.folder / (name + ".S")
        binary = self.folder / name
        path.write_text(source)
        subprocess.run(["cc", "-nostdlib", "-static", "-no-pie", str(path),
                        "-o", str(binary)], check=True,
                       capture_output=True, timeout=30)
        return binary

    def test_minimum_nan_ties_signs_rex_memory_alias_and_carry(self):
        binary = self.build("positive", ASM)
        host = subprocess.run([str(binary)], capture_output=True, timeout=10)
        guest = subprocess.run([str(self.runner), str(binary)],
                               capture_output=True, timeout=30)
        qword = lambda number: number.to_bytes(8, "little")
        low = (0x400a000000000000, 0xc01c000000000000,
               0x8000000000000000, 0,
               0x400a000000000000, 0x7ff8000000000071,
               0x400a000000000000, 0x4000000000000000,
               0x7ff800000000005a)
        expected = (b"".join(qword(num) + qword(0x1111111111111111)
                             for num in low) + qword(1))
        self.assertEqual(len(expected), 152)
        self.assertEqual(host.returncode, 0, host.stderr)
        self.assertEqual(host.stdout, expected)
        self.assertEqual(guest.returncode, 0, guest.stderr)
        self.assertEqual(guest.stdout, host.stdout)
        self.assertIn(b"COMPACT_JOBS_RESULT status=0 exited=1 exit=0",
                      guest.stderr)

    def test_unmapped_m64_fails_closed_just_like_linux(self):
        binary = self.build("unmapped", r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
 xor eax,eax
 minsd xmm0,QWORD PTR [rax]
 mov eax,60
 xor edi,edi
 syscall
""")
        host = subprocess.run([str(binary)], capture_output=True, timeout=10)
        guest = subprocess.run([str(self.runner), str(binary)],
                               capture_output=True, timeout=15)
        self.assertEqual(host.returncode, -11, host.stderr)
        self.assertEqual(guest.returncode, 2, guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=2", guest.stderr)

    def test_unsupported_minss_and_packed_variants_stay_explicit(self):
        # These are distinct F3/66 instructions; they must never silently
        # execute the scalar F2 MINSD semantics.
        for name, code in (("minss", "f3 0f 5d c1"),
                           ("minpd", "66 0f 5d c1")):
            with self.subTest(name=name):
                binary = self.build(name, """
.intel_syntax noprefix
.global _start
.section .text
_start:
 .byte """ + ",".join("0x" + pair for pair in code.split()) + """
 mov eax,60
 xor edi,edi
 syscall
""")
                guest = subprocess.run(
                    [str(self.runner), str(binary)],
                    capture_output=True, timeout=15)
                self.assertEqual(guest.returncode, 2, guest.stderr)
                self.assertIn(b"COMPACT_JOBS_RESULT status=3", guest.stderr)


if __name__ == "__main__":
    unittest.main()
