# SPDX-License-Identifier: AGPL-3.0-only
"""Intel COMISS/UCOMISS scalar binary32 EFLAGS: real Linux vs Ryzova VM.

The same source-built static AMD64 ELF executes once on the Linux host
and once on the original bounded Ryzova C interpreter. MXCSR exceptions
and non-default floating-point modes are deliberately *not* qualified.
"""
import struct
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(n+'.c') for n in (
    'elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe'
)]
BITS={
    'one':0x3f800000, 'two':0x40000000,
    'zero':0, 'minuszero':0x80000000,
    'minusinf':0xff800000,'plusinf':0x7f800000,
    'qnan':0x7fc00000,'snan':0x7f800001,
    'subnorm':0x00000001,'negative_subnorm':0x80000001
}
CASES=[
    ('one','two','comiss',1),
    ('two','one','comiss',0),
    ('one','one','comiss',0x40),
    ('minuszero','zero','comiss',0x40),
    ('minusinf','one','comiss',1),
    ('plusinf','minusinf','comiss',0),
    ('qnan','one','comiss',0x45),
    ('snan','one','ucomiss',0x45),
    ('subnorm','zero','comiss',0),
    ('negative_subnorm','minuszero','comiss',1)
]


def assembly():
    lines=['.intel_syntax noprefix','.section .text','.global _start','_start:']
    for i,(left,right,opcode,_) in enumerate(CASES):
        lines.extend([
            f'  mov eax, DWORD PTR [rip+{left}]',
            '  movd xmm0,eax',
            f'  {opcode} xmm0, DWORD PTR [rip+{right}]',
            '  pushfq','  pop rax','  and eax, 0x8d5',
            f'  mov WORD PTR [rip+output+{i*2}],ax',
        ])
    lines.extend([
        '  mov eax,1','  mov edi,1','  lea rsi,[rip+output]',
        f'  mov edx,{len(CASES)*2}','  syscall',
        '  mov eax,60','  xor edi,edi','  syscall',
        '.section .rodata'
    ])
    for name,bits in BITS.items():
        lines.append(f'{name}: .long 0x{bits:08x}')
    lines.extend(['.section .bss','.balign 16',
                  f'output: .zero {len(CASES)*2}'])
    return '\n'.join(lines)+'\n'


class ComissDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='clx-comiss-')
        cls.directory=Path(cls.temp.name)
        cls.runner=cls.directory/'runner'
        cls.binary=cls.directory/'comiss'
        asm=cls.directory/'comiss.S'
        asm.write_text(assembly())
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       check=True,capture_output=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',str(asm),
                        '-o',str(cls.binary)],
                       check=True,capture_output=True,timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_ordered_unordered_nan_infinity_signed_zero_subnormal_flags(self):
        host=subprocess.run([str(self.binary)],capture_output=True,timeout=8)
        guest=subprocess.run([str(self.runner),str(self.binary)],
                             capture_output=True,timeout=25)
        expected=b''.join(struct.pack('<H',flags) for *_,flags in CASES)
        self.assertEqual(host.returncode,0,host.stderr)
        self.assertEqual(host.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,host.stdout)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_illegal_repeat_prefix_and_dereference_invalid_address_fail_closed(self):
        from test_phase9_image_admission import executable
        bad=self.directory/'wrong-prefix'
        bad.write_bytes(executable(code=bytes([0xf3,0x66,0x0f,0x2f,0xc1])))
        result=subprocess.run([str(self.runner),str(bad)],
                              capture_output=True,timeout=10)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',result.stderr)

        unmapped=self.directory/'unmapped-comiss'
        # mov rax,0; comiss xmm0,DWORD PTR [rax]
        unmapped.write_bytes(executable(code=bytes([
            0x48,0xc7,0xc0,0,0,0,0,0x0f,0x2f,0
        ])))
        result=subprocess.run([str(self.runner),str(unmapped)],
                              capture_output=True,timeout=10)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',result.stderr)


if __name__=='__main__':
    unittest.main()
