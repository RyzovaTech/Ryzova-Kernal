# SPDX-License-Identifier: AGPL-3.0-only
"""Same source-built AMD64 ELF on Linux and bounded Ryzova VM.

Covers 0F 12 MOVHLPS register and MOVLPS unaligned m64 load, 0F 13
MOVLPS m64 store, self-aliases, REX-XMM8, EFLAGS and explicit failures.
Does not imply complete SSE ABI, CPython or V1 acceptance.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "ryzova/compat/linux"
SOURCES = [CORE / (n + ".c") for n in (
    "elf64", "namespace", "syscall", "subset_vm", "memory",
    "process", "cpu", "jobs", "jobs_probe"
)]
POSITIVE = r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
 movdqu xmm0, XMMWORD PTR [rip + src]
 movdqu xmm2, XMMWORD PTR [rip + dst]
 stc
 movhlps xmm2, xmm0
 movdqu XMMWORD PTR [rip + out0], xmm2
 pushfq
 pop rax
 and eax, 1
 mov QWORD PTR [rip + flags], rax
 movdqu xmm3, XMMWORD PTR [rip + src]
 movhlps xmm3, xmm3
 movdqu XMMWORD PTR [rip + out1], xmm3
 movdqu xmm8, XMMWORD PTR [rip + dst]
 movhlps xmm8, xmm0
 movdqu XMMWORD PTR [rip + out2], xmm8
 movdqu xmm4, XMMWORD PTR [rip + dst]
 movlps xmm4, QWORD PTR [rip + memory_load]
 movdqu XMMWORD PTR [rip + out3], xmm4
 movlps QWORD PTR [rip + out4], xmm4
 mov eax, 1
 mov edi, 1
 lea rsi, [rip + out0]
 mov edx, 80
 syscall
 mov eax, 60
 xor edi,edi
 syscall
.section .data
.balign 16
src: .quad 0x1111111111111111,0x2222222222222222
dst: .quad 0xaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbb
.byte 0xef
memory_load: .quad 0x0123456789abcdef
.section .bss
.balign 16
out0: .zero 16
out1: .zero 16
out2: .zero 16
out3: .zero 16
out4: .zero 8
flags: .zero 8
"""


class MovhlpsDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ryz-movhlps-")
        cls.folder = Path(cls.temp.name)
        cls.runner = cls.folder / "runner"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             *map(str, SOURCES), "-o", str(cls.runner)],
            check=True, capture_output=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self, name, asm):
        source = self.folder / (name + ".S")
        binary = self.folder / name
        source.write_text(asm)
        subprocess.run(["cc", "-nostdlib", "-static", "-no-pie",
                        str(source), "-o", str(binary)],
                       check=True, capture_output=True, timeout=30)
        return binary

    def test_register_memory_alias_rex_flags_exact_linux_bytes(self):
        binary = self.build("positive", POSITIVE)
        host = subprocess.run([str(binary)], capture_output=True, timeout=10)
        guest = subprocess.run([str(self.runner), str(binary)],
                               capture_output=True, timeout=25)
        q = lambda n: n.to_bytes(8, "little")
        pair = q(0x2222222222222222) + q(0xbbbbbbbbbbbbbbbb)
        value = q(0x0123456789abcdef)
        expected = (pair + q(0x2222222222222222) * 2 + pair +
                    value + q(0xbbbbbbbbbbbbbbbb) + value + q(1))
        self.assertEqual(len(expected), 80)
        self.assertEqual(host.returncode, 0, host.stderr)
        self.assertEqual(host.stdout, expected)
        self.assertEqual(guest.returncode, 0, guest.stderr)
        self.assertEqual(guest.stdout, host.stdout)
        self.assertIn(b"COMPACT_JOBS_RESULT status=0 exited=1 exit=0",
                      guest.stderr)

    def test_movlps_register_store_is_invalid_on_linux_and_vm(self):
        asm = r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
 .byte 0x0f, 0x13, 0xc1
 mov eax, 60
 xor edi, edi
 syscall
"""
        binary = self.build("bad-13-reg", asm)
        host = subprocess.run([str(binary)], capture_output=True, timeout=10)
        guest = subprocess.run([str(self.runner), str(binary)],
                               capture_output=True, timeout=20)
        self.assertEqual(host.returncode, -4, host.stderr)
        self.assertEqual(guest.returncode, 2, guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=3", guest.stderr)

    def test_unmapped_memory_load_is_denied(self):
        asm = r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
 xor eax,eax
 movlps xmm0, QWORD PTR [rax]
 mov eax, 60
 xor edi, edi
 syscall
"""
        binary = self.build("unmapped-load", asm)
        host = subprocess.run([str(binary)], capture_output=True, timeout=10)
        guest = subprocess.run([str(self.runner), str(binary)],
                               capture_output=True, timeout=20)
        self.assertEqual(host.returncode, -11, host.stderr)
        self.assertEqual(guest.returncode, 2, guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=2", guest.stderr)


if __name__ == "__main__":
    unittest.main()
