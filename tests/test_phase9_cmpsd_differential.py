# SPDX-License-Identifier: AGPL-3.0-only
"""Source-built Linux versus Ryzova SSE2 CMPSD F2 0F C2 /r imm8.

Finite predicates 0..7, signed zero, qNaN, unaligned m64, REX XMM8+,
self-alias, exact low all-ones/zero masks, unchanged high XMM and carry.
The emulator does NOT model MXCSR exception flags/traps or reserved
predicates, and this does not qualify complete AMD64 ABI or CPython.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/"ryzova/compat/linux"
SOURCES=[CORE/(name+".c") for name in (
    "elf64","namespace","syscall","subset_vm","memory",
    "process","cpu","jobs","jobs_probe"
)]
# dest, source, predicate, expected truth, unaligned memory, register alias
CASES=(
    ("two","three",0,False,False,False),
    ("two","three",1,True,False,False),
    ("two","three",2,True,False,False),
    ("two","three",3,False,False,False),
    ("two","three",4,True,False,False),
    ("two","three",5,False,False,False),
    ("two","three",6,False,False,False),
    ("two","three",7,True,False,False),
    ("nan","three",3,True,False,False),
    ("nan","three",6,True,False,False),
    ("zero","minuszero",0,True,False,False),
    ("four","three",6,True,False,False),
    ("two","three",2,True,True,False),
    ("two","two",0,True,False,True),
)


def positive_assembly():
    lines=[".intel_syntax noprefix",".section .text",".global _start",
           "_start:","stc"]
    for i,(dst,src,predicate,truth,is_memory,is_alias) in enumerate(CASES):
        lines.append(f"movdqu xmm{i},XMMWORD PTR [rip + {dst}]")
        if is_alias:
            lines.append(f"cmpsd xmm{i},xmm{i},{predicate}")
        elif is_memory:
            lines.append(f"cmpsd xmm{i},QWORD PTR [rip + unaligned_three],{predicate}")
        else:
            lines.append(f"movdqu xmm15,XMMWORD PTR [rip + {src}]")
            lines.append(f"cmpsd xmm{i},xmm15,{predicate}")
        lines.append(f"movdqu XMMWORD PTR [rip + out{i}],xmm{i}")
    lines += [
        "pushfq","pop rax","and eax,1","mov QWORD PTR [rip + carry],rax",
        "mov eax,1","mov edi,1","lea rsi,[rip + out0]",
        f"mov edx,{len(CASES)*16+8}","syscall",
        "mov eax,60","xor edi,edi","syscall",
        ".section .data",".balign 16",
        "two: .quad 0x4000000000000000,0x1111111111111111",
        "three: .quad 0x4008000000000000,0x1111111111111111",
        "four: .quad 0x4010000000000000,0x1111111111111111",
        "nan: .quad 0x7ff8000000000042,0x1111111111111111",
        "zero: .quad 0,0x1111111111111111",
        "minuszero: .quad 0x8000000000000000,0x1111111111111111",
        ".byte 0x77","unaligned_three: .quad 0x4008000000000000",
        ".section .bss",".balign 16"
    ]
    lines += [f"out{i}: .zero 16" for i in range(len(CASES))]
    lines.append("carry: .zero 8")
    return "\n".join(lines)+"\n"


class CmpsdDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="ryz-cmpsd-")
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
        subprocess.run(["cc","-nostdlib","-static","-no-pie",str(path),
                        "-o",str(binary)],check=True,
                       capture_output=True,timeout=30)
        return binary

    def test_predicates_nan_signed_zero_unaligned_rex_and_eflags(self):
        elf=self.build("positive",positive_assembly())
        native=subprocess.run([str(elf)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(elf)],
                             capture_output=True,timeout=35)
        q=lambda x:x.to_bytes(8,"little")
        high=q(0x1111111111111111)
        expected=b"".join(
            q(0xffffffffffffffff if case[3] else 0)+high for case in CASES
        )+q(1)
        self.assertEqual(len(expected),232)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(native.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        self.assertIn(b"COMPACT_JOBS_RESULT status=0 exited=1 exit=0",
                      guest.stderr)

    def test_unmapped_unaligned_m64_denied_like_linux(self):
        elf=self.build("badmem",r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    xor eax,eax
    cmpsd xmm0,QWORD PTR [rax],6
    mov eax,60
    xor edi,edi
    syscall
""")
        native=subprocess.run([str(elf)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(elf)],
                             capture_output=True,timeout=20)
        self.assertEqual(native.returncode,-11,native.stderr)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b"COMPACT_JOBS_RESULT status=2",guest.stderr)

    def test_other_prefix_and_reserved_predicate_fail_closed(self):
        # Unprefixed 0F C2 has different packed SSE semantics; imm8 above
        # 7 uses reserved bits and is deliberately outside this ABI subset.
        for name,op in (("cmpps","0x0f,0xc2,0xc1,0x06"),
                        ("reserved","0xf2,0x0f,0xc2,0xc1,0x08")):
            with self.subTest(name=name):
                elf=self.build(name,"""
.intel_syntax noprefix
.global _start
.section .text
_start:
 .byte """+op+"""
 mov eax,60
 xor edi,edi
 syscall
""")
                guest=subprocess.run([str(self.runner),str(elf)],
                                     capture_output=True,timeout=20)
                self.assertEqual(guest.returncode,2,guest.stderr)
                self.assertIn(b"COMPACT_JOBS_RESULT status=3",guest.stderr)


if __name__=="__main__":
    unittest.main()
