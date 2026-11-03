# SPDX-License-Identifier: AGPL-3.0-only
"""Linux vs original Ryzova ADDSD/DIVSD IEEE binary64 differential.

The CPU uses only bounded integer arithmetic, not the host's floating-point
unit. Full MXCSR exception flags / DAZ / FTZ / non-default rounding and
production ABI acceptance remain explicitly outside this research test.
"""
from pathlib import Path
import math
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(n+'.c') for n in
         ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
HIGH=bytes(range(0xa0,0xa8))
PAIR_CASES=[
    ('add',1.,2.),('add',0.1,0.2),('add',1.,-1.),
    ('add',-0.,-0.),('add',0.,-0.),
    ('add',1e300,1e-300),('add',1e-300,-1e-300),
    ('add',5e-324,5e-324),('add',-5e-324,5e-324),
    ('add',2.2250738585072014e-308,-5e-324),
    ('add',-1e300,1e300),
    ('div',6.,3.),('div',-7.,2.),('div',1.,3.),('div',0.1,3.),
    ('div',5e-324,1.),('div',1e-300,1e300),
    ('div',1e300,1e-300),('div',2.2250738585072014e-308,2.),
    ('div',-1.,1e308),('div',-0.,2.),('div',2.,-1.),
]


def raw64(value):
    return int.from_bytes(struct.pack('<d',value),'little')


def assembly():
    lines=['.intel_syntax noprefix','.section .text','.global _start','_start:']
    expected=[]
    for i,(operation,a,b) in enumerate(PAIR_CASES):
        ins='addsd' if operation=='add' else 'divsd'
        lines.extend([
            '  movdqu xmm0,XMMWORD PTR [rip+left_'+str(i)+']',
        ])
        if i%2:
            lines.append('  movdqu xmm1,XMMWORD PTR [rip+right_'+str(i)+']')
            lines.append(f'  {ins} xmm0,xmm1')
        else:
            lines.append(f'  {ins} xmm0,QWORD PTR [rip+right_{i}]')
        lines.append(f'  movdqu XMMWORD PTR [rip+outbuf+{16*i}],xmm0')
        actual=a+b if operation=='add' else a/b
        expected.append(struct.pack('<d',actual)+HIGH)
    length=len(PAIR_CASES)*16
    lines.extend(['  mov eax,1','  mov edi,1','  lea rsi,[rip+outbuf]',
                  f'  mov edx,{length}','  syscall',
                  '  mov eax,60','  xor edi,edi','  syscall',
                  '.section .rodata','.balign 16'])
    for i,(_,a,b) in enumerate(PAIR_CASES):
        lines.extend([f'left_{i}: .quad 0x{raw64(a):016x}',
                      '  .byte '+','.join(str(v) for v in HIGH),
                      f'right_{i}: .quad 0x{raw64(b):016x}',
                      '  .quad 0x0123456789abcdef'])
    lines.extend(['.section .bss','.balign 16',f'outbuf: .zero {length}'])
    return '\n'.join(lines)+'\n',b''.join(expected)


class DoubleArithmeticDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='clx-adddivsd-')
        cls.dir=Path(cls.temp.name)
        cls.runner=cls.dir/'runner'
        cls.binary=cls.dir/'scalar-add-div'
        source=cls.dir/'scalar-add-div.S'
        source.write_text(assembly()[0])
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       check=True,capture_output=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',
                        str(source),'-o',str(cls.binary)],
                       check=True,capture_output=True,timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_soft_integer_binary64_add_div_register_memory_and_ieee_rounding(self):
        host=subprocess.run([str(self.binary)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(self.binary)],
                             capture_output=True,timeout=30)
        expected=assembly()[1]
        self.assertEqual(host.returncode,0,host.stderr)
        self.assertEqual(host.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,host.stdout)
        self.assertEqual(len(guest.stdout),len(PAIR_CASES)*16)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_unmapped_scalar_double_source_fails_closed(self):
        from test_phase9_image_admission import executable
        image=self.dir/'bad-scalar-divsd'
        # mov rax,0; divsd xmm0,QWORD PTR [rax]
        image.write_bytes(executable(code=bytes([
             0x48,0xc7,0xc0,0,0,0,0,
             0xf2,0x0f,0x5e,0x00
        ])))
        result=subprocess.run([str(self.runner),str(image)],
                              capture_output=True,timeout=10)
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',result.stderr)


if __name__=='__main__':
    unittest.main()
