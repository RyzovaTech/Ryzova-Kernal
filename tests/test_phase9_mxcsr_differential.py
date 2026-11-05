# SPDX-License-Identifier: AGPL-3.0-only
"""Host/guest differential for bounded SSE MXCSR default-control instructions.

This only qualifies STMXCSR m32 and LDMXCSR of default 0x1f80; it does not
implement nondefault rounding, sticky exception bits, DAZ, FTZ, or full AMD64.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "ryzova/compat/linux"
SOURCES = [CORE / (s + ".c") for s in (
    "elf64", "namespace", "syscall", "subset_vm", "memory", "process",
    "cpu", "jobs", "jobs_probe"
)]
POSITIVE = r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    stc
    stmxcsr DWORD PTR [rip + out0]
    ldmxcsr DWORD PTR [rip + default]
    stmxcsr DWORD PTR [rip + out1]
    pushfq
    pop rax
    and eax, 1
    mov QWORD PTR [rip + flags], rax
    sub rsp, 8
    stmxcsr DWORD PTR [rsp]
    mov eax, DWORD PTR [rsp]
    mov DWORD PTR [rip + out2], eax
    add rsp, 8
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + out0]
    mov edx, 20
    syscall
    mov eax, 60
    xor edi, edi
    syscall
.section .data
out0: .long 0
out1: .long 0
out2: .long 0
flags: .quad 0
default: .long 0x1f80
"""


class MxcsrDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ryz-mxcsr-")
        cls.directory = Path(cls.temp.name)
        cls.runner = cls.directory / "runner"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             *map(str, SOURCES), "-o", str(cls.runner)],
            capture_output=True, check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build(self, name, body):
        path = self.directory / (name + ".S")
        binary = self.directory / name
        path.write_text(body)
        subprocess.run(
            ["cc", "-nostdlib", "-static", "-no-pie",
             str(path), "-o", str(binary)],
            capture_output=True, check=True, timeout=30)
        return binary

    def test_default_mxcsr_stack_memory_and_flags_against_linux(self):
        binary = self.build("positive", POSITIVE)
        host = subprocess.run([str(binary)], capture_output=True, timeout=8)
        guest = subprocess.run(
            [str(self.runner), str(binary)], capture_output=True, timeout=20)
        expect = (0x1f80).to_bytes(4, "little") * 3 + (1).to_bytes(8, "little")
        self.assertEqual(host.returncode, 0, host.stderr)
        self.assertEqual(host.stdout, expect)
        self.assertEqual(guest.returncode, 0, guest.stderr)
        self.assertEqual(guest.stdout, host.stdout)
        self.assertIn(b"COMPACT_JOBS_RESULT status=0 exited=1 exit=0",
                      guest.stderr)

    def test_valid_but_nondefault_control_fails_closed(self):
        asm = r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    ldmxcsr DWORD PTR [rip + value]
    mov eax, 60
    xor edi, edi
    syscall
.section .data
value: .long 0x3f80
"""
        binary = self.build("nondefault", asm)
        host = subprocess.run([str(binary)], capture_output=True, timeout=8)
        guest = subprocess.run(
            [str(self.runner), str(binary)], capture_output=True, timeout=20)
        self.assertEqual(host.returncode, 0, host.stderr)
        self.assertEqual(guest.returncode, 2, guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=3", guest.stderr)

    def test_register_operands_and_unmapped_m32_rejected(self):
        register = r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    .byte 0x0f, 0xae, 0xd8
    mov eax, 60
    xor edi, edi
    syscall
"""
        memory = r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    xor eax, eax
    stmxcsr DWORD PTR [rax]
    mov eax, 60
    xor edi, edi
    syscall
"""
        for name, asm, host_status, guest_status in (
                ("register", register, -4, 3),
                ("unmapped", memory, -11, 2)):
            with self.subTest(name=name):
                binary = self.build(name, asm)
                host = subprocess.run(
                    [str(binary)], capture_output=True, timeout=8)
                guest = subprocess.run(
                    [str(self.runner), str(binary)], capture_output=True, timeout=20)
                self.assertEqual(host.returncode, host_status, host.stderr)
                self.assertEqual(guest.returncode, 2, guest.stderr)
                self.assertIn(
                    ("COMPACT_JOBS_RESULT status=" + str(guest_status)).encode(),
                    guest.stderr)


if __name__ == "__main__":
    unittest.main()
