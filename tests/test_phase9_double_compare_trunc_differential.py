# SPDX-License-Identifier: AGPL-3.0-only
"""Source-built Linux AMD64 vs Ryzova guest scalar binary64 compare/truncate.

Only default masked MXCSR conditions and integer/flags results are exercised.
No MXCSR sticky flags, unmasked exceptions or complete ABI claims.
"""
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(x+'.c') for x in (
    'elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
VALUE_BITS={
    'one':0x3ff0000000000000,'two':0x4000000000000000,
    'zero':0,'minuszero':0x8000000000000000,
    'negative':0xbff0000000000000,
    'plusinf':0x7ff0000000000000,'minusinf':0xfff0000000000000,
    'qnan':0x7ff8000000000001,'snan':0x7ff0000000000001,
    'subnorm':1,'negative_subnorm':0x8000000000000001,
}
COMPARE=[
    ('one','two',1),('two','one',0),('one','one',0x40),
    ('minuszero','zero',0x40),('negative','one',1),
    ('minusinf','one',1),('plusinf','minusinf',0),
    ('qnan','one',0x45),('snan','one',0x45),
    ('subnorm','zero',0),('negative_subnorm','minuszero',1),
]
# (bits, destination width, expected uint64 after x86 GPR write).
CONVERSIONS=[
    (0x3ffc000000000000,64,1),  # +1.75
    (0xbffc000000000000,64,0xffffffffffffffff), # -1.75
    (0x3fe0000000000000,64,0),  # +0.5
    (0xbfe0000000000000,64,0),  # -0.5
    (0x43e0000000000000,64,0x8000000000000000), # +2^63 overflow
    (0xc3e0000000000000,64,0x8000000000000000), # -2^63 exact
    (0x7ff8000000000001,64,0x8000000000000000), # NaN
    (0x7ff0000000000000,64,0x8000000000000000), # +inf
    (0x4340000000000001,64,0x0020000000000002), # 2^53 + 2
    (0x3ffc000000000000,32,1),
    (0xbffc000000000000,32,0xffffffff),
    (0x41e0000000000000,32,0x80000000), # +2^31 overflow
    (0xc1e0000000000000,32,0x80000000), # -2^31 exact
    (0x7ff8000000000001,32,0x80000000), # NaN
]


def asm_and_result():
    lines=['.intel_syntax noprefix','.section .text','.global _start','_start:']
    for i,(left,right,_) in enumerate(COMPARE):
        opcode='ucomisd' if i%2 else 'comisd'
        lines.append(f'  movsd xmm0, QWORD PTR [rip+{left}]')
        if i%2:
            lines += [f'  movsd xmm1, QWORD PTR [rip+{right}]',
                      f'  {opcode} xmm0, xmm1']
        else:
            lines.append(f'  {opcode} xmm0, QWORD PTR [rip+{right}]')
        lines += ['  pushfq','  pop rax','  and eax, 0x8d5',
                  f'  mov WORD PTR [rip+flags+{2*i}],ax']
    for i,(_bits,width,_expected) in enumerate(CONVERSIONS):
        lines += [f'  movsd xmm0, QWORD PTR [rip+conversion_{i}]',
                  f'  cvttsd2si {"rax" if width==64 else "eax"}, xmm0',
                  f'  mov QWORD PTR [rip+values+{8*i}],rax']
    lines += ['  mov eax,1','  mov edi,1','  lea rsi,[rip+flags]',
              f'  mov edx,{2*len(COMPARE)}','  syscall',
              '  mov eax,1','  mov edi,1','  lea rsi,[rip+values]',
              f'  mov edx,{8*len(CONVERSIONS)}','  syscall',
              '  mov eax,60','  xor edi,edi','  syscall',
              '.section .rodata']
    for name,bits in VALUE_BITS.items():
        lines += [f'{name}: .quad 0x{bits:016x}']
    for i,(bits,_,_) in enumerate(CONVERSIONS):
        lines += [f'conversion_{i}: .quad 0x{bits:016x}']
    lines += ['.section .bss','.balign 16',
              f'flags: .zero {2*len(COMPARE)}',
              f'values: .zero {8*len(CONVERSIONS)}']
    expected=b''.join(struct.pack('<H',flags) for _,__,flags in COMPARE)
    expected+=b''.join(struct.pack('<Q',value) for _,__,value in CONVERSIONS)
    return '\n'.join(lines)+'\n',expected


class DoubleCompareTruncDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='clx-double-trunc-')
        cls.directory=Path(cls.temp.name)
        cls.binary=cls.directory/'compare-trunc'
        cls.runner=cls.directory/'runner'
        src=cls.directory/'compare-trunc.S'
        src.write_text(asm_and_result()[0])
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       capture_output=True,check=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',str(src),
                        '-o',str(cls.binary)],
                       capture_output=True,check=True,timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_comisd_ucomisd_cvttsd2si_native_linux_and_guest_results_match(self):
        host=subprocess.run([str(self.binary)],capture_output=True,timeout=8)
        guest=subprocess.run([str(self.runner),str(self.binary)],
                             capture_output=True,timeout=25)
        expected=asm_and_result()[1]
        self.assertEqual(host.returncode,0,host.stderr)
        self.assertEqual(host.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,host.stdout)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_unmapped_operands_and_illegal_prefix_fail_closed(self):
        from test_phase9_image_admission import executable
        for name,code,status in [
            ('bad-comisd',[0x48,0xc7,0xc0,0,0,0,0,0x66,0x0f,0x2f,0x00],2),
            ('bad-convert',[0x48,0xc7,0xc0,0,0,0,0,0xf2,0x48,0x0f,0x2c,0x00],2),
            ('illegal-prefix',[0xf3,0x66,0x0f,0x2f,0xc1],3),
        ]:
            with self.subTest(name=name):
                binary=self.directory/(name+'.elf')
                binary.write_bytes(executable(code=bytes(code)))
                result=subprocess.run([str(self.runner),str(binary)],
                                      capture_output=True,timeout=10)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertIn(f'COMPACT_JOBS_RESULT status={status}'.encode(),
                              result.stderr)


if __name__=='__main__':
    unittest.main()
