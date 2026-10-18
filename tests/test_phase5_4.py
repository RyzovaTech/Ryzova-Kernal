# SPDX-License-Identifier: AGPL-3.0-only
"""Real statically linked Linux ELF instructions interpreted by virtual ABI."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/linux"
GOOD=r'''
.global _start
.section .text
_start:
    mov $1, %eax
    mov $1, %edi
    lea text(%rip), %rsi
    mov $19, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
.section .rodata
text:
    .ascii "RYZOVA_LINUX_HELLO\n"
'''
LOOP=r'''
.global _start
.section .text
_start:
    jmp _start
'''
UNSUPPORTED=r'''
.global _start
.section .text
_start:
    int3
'''
DANGEROUS=r'''
.global _start
.section .text
_start:
    mov $257, %eax
    xor %edi,%edi
    syscall
    mov $60,%eax
    xor %edi,%edi
    syscall
'''
class TestPhase54(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="ryzova-real-elf-")
        cls.dir=Path(cls.temp.name)
        cls.cc=os.environ.get("PHASE5_CC","gcc")
        cfiles=["elf64.c","namespace.c","syscall.c","subset_vm.c","subset_vm_probe.c"]
        args=[cls.cc,"-std=c11","-O2","-Wall","-Wextra","-Werror","-pedantic",
              *(str(C/p) for p in cfiles),"-o",str(cls.dir/"run")]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            args[1:1]=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        x=subprocess.run(args,capture_output=True,text=True)
        if x.returncode: raise AssertionError(x.stderr)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def make(self,name,source):
        asm=self.dir/(name+".S")
        elf=self.dir/name
        asm.write_text(source)
        p=subprocess.run(["gcc","-nostdlib","-static","-no-pie",str(asm),"-o",str(elf)],
                         capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        return elf
    def run_vm(self,binary):
        return subprocess.run([str(self.dir/"run"),str(binary)],
                              capture_output=True,text=True,timeout=5)
    def test_true_linux_elf_bytes_write_and_exit(self):
        elf=self.make("hello",GOOD)
        p=self.run_vm(elf)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout,"RYZOVA_LINUX_HELLO\n")
        self.assertIn("status=0 exited=1 exit_code=0",p.stderr)
        self.assertIn("syscalls=2",p.stderr)
    def test_native_reference_output_matches_interpreter(self):
        elf=self.make("reference",GOOD)
        native=subprocess.run([str(elf)],capture_output=True,text=True,timeout=5)
        vm=self.run_vm(elf)
        self.assertEqual(native.stdout,vm.stdout)
        self.assertEqual(native.returncode,0)
        self.assertEqual(vm.returncode,0)
    def test_unknown_x86_opcode_fails_closed(self):
        p=self.run_vm(self.make("unsupported",UNSUPPORTED))
        self.assertEqual(p.returncode,2)
        self.assertIn("status=3",p.stderr)
    def test_unimplemented_linux_syscall_fails_closed(self):
        p=self.run_vm(self.make("badcall",DANGEROUS))
        self.assertEqual(p.returncode,2)
        self.assertIn("status=5",p.stderr)
    def test_endless_loop_has_instruction_budget(self):
        p=self.run_vm(self.make("loop",LOOP))
        self.assertEqual(p.returncode,2)
        self.assertIn("status=4",p.stderr)
        self.assertIn("steps=2048",p.stderr)
    def test_invalid_header_is_rejected(self):
        elf=self.make("corrupt",GOOD)
        data=bytearray(elf.read_bytes());data[0]=0
        elf.write_bytes(data)
        p=self.run_vm(elf)
        self.assertEqual(p.returncode,2)
        self.assertIn("status=1",p.stderr)
if __name__=="__main__":
    unittest.main()
