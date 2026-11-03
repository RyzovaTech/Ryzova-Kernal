# SPDX-License-Identifier: AGPL-3.0-only
"""Real Linux vs Ryzova scalar SSE2 double-precision conversion/moves.

No native host floating point is used inside the Ryzova implementation.
Only default MXCSR RN-even conversion is claimed; other rounding modes
and MXCSR FP status/exceptions are not implemented.
"""
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(x+'.c') for x in
         ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
VALUES=[0,1,-1,1<<53,(1<<53)+1,(1<<53)+3,(1<<63)-1,-(1<<63),-(1<<53)-1]
MARKER=bytes(range(16))
OTHER=bytes(range(0x20,0x30))


def program():
    lines=['.intel_syntax noprefix','.section .text','.global _start','_start:']
    expected=[]
    words={}
    for i,num in enumerate(VALUES):
        name=f'value_{i}'
        words[name]=num&((1<<64)-1)
        lines.extend([
            '  movdqu xmm0, XMMWORD PTR [rip+marker]',
            f'  mov rax, QWORD PTR [rip+{name}]',
            '  cvtsi2sd xmm0,rax',
            f'  movdqu XMMWORD PTR [rip+output+{16*i}],xmm0'
        ])
        expected.append(struct.pack('<d',float(num))+MARKER[8:])
    pos=len(expected)*16
    words['integer32']=(1<<64)-(1<<31)
    lines.extend([
        '  movdqu xmm0, XMMWORD PTR [rip+marker]',
        '  mov eax, DWORD PTR [rip+integer32]',
        '  cvtsi2sd xmm0,eax',
        f'  movdqu XMMWORD PTR [rip+output+{pos}],xmm0'
    ])
    expected.append(struct.pack('<d',float(-(1<<31)))+MARKER[8:])
    pos+=16
    lines.extend([
        '  movdqu xmm0,XMMWORD PTR [rip+marker]',
        '  cvtsi2sd xmm0,QWORD PTR [rip+value_7]',
        f'  movdqu XMMWORD PTR [rip+output+{pos}],xmm0'
    ])
    expected.append(struct.pack('<d',float(-(1<<63)))+MARKER[8:])
    pos+=16
    lines.extend([
        '  movdqu xmm0,XMMWORD PTR [rip+marker]',
        '  movsd xmm0,QWORD PTR [rip+fraction]',
        f'  movdqu XMMWORD PTR [rip+output+{pos}],xmm0'
    ])
    expected.append(struct.pack('<Q',0x3ff199999999999a)+bytes(8))
    pos+=16
    lines.extend([
        '  movdqu xmm0,XMMWORD PTR [rip+marker]',
        '  movdqu xmm1,XMMWORD PTR [rip+other]',
        '  movsd xmm0,xmm1',
        f'  movdqu XMMWORD PTR [rip+output+{pos}],xmm0'
    ])
    expected.append(OTHER[:8]+MARKER[8:])
    pos+=16
    lines.extend([
        '  movdqu xmm1,XMMWORD PTR [rip+marker]',
        '  movdqu xmm0,XMMWORD PTR [rip+other]',
        '  .byte 0xf2,0x0f,0x11,0xc1',
        f'  movdqu XMMWORD PTR [rip+output+{pos}],xmm1'
    ])
    expected.append(OTHER[:8]+MARKER[8:])
    pos+=16
    lines.extend([
        '  movdqu xmm0,XMMWORD PTR [rip+other]',
        f'  movsd QWORD PTR [rip+output+{pos}],xmm0'
    ])
    expected.append(OTHER[:8]+bytes([0xa5]*8))
    pos+=16
    lines.extend([
        '  mov eax,1','  mov edi,1','  lea rsi,[rip+output]',
        f'  mov edx,{pos}','  syscall',
        '  mov eax,60','  xor edi,edi','  syscall',
        '.section .rodata','.balign 16',
        'marker: .byte '+','.join(map(str,MARKER)),
        'other: .byte '+','.join(map(str,OTHER)),
        'fraction: .quad 0x3ff199999999999a'
    ])
    for name,bits in words.items():
        lines.append(f'{name}: .quad 0x{bits:016x}')
    lines.extend(['.section .data','.balign 16',
                  f'output: .fill {pos},1,0xa5'])
    return '\n'.join(lines)+'\n', b''.join(expected)


class DoubleScalarDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='clx-double-')
        cls.directory=Path(cls.temp.name)
        cls.runner=cls.directory/'runner'
        cls.binary=cls.directory/'scalar-double'
        source=cls.directory/'scalar-double.S'
        source.write_text(program()[0])
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       check=True,capture_output=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',
                        str(source),'-o',str(cls.binary)],
                       check=True,capture_output=True,timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_signed_64_and_32bit_int_to_double_ties_even_and_movsd_register_memory(self):
        native=subprocess.run([str(self.binary)],capture_output=True,timeout=10)
        guest=subprocess.run([str(self.runner),str(self.binary)],
                             capture_output=True,timeout=25)
        expected=program()[1]
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(native.stdout,expected)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        self.assertEqual(len(guest.stdout),240)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_invalid_guest_operand_memory_still_denied(self):
        from test_phase9_image_admission import executable
        image=self.directory/'invalid-cvtsi2sd'
        # mov rax,0 ; cvtsi2sd xmm0,QWORD PTR [rax] ; unmapped memory
        image.write_bytes(executable(code=bytes([
            0x48,0xc7,0xc0,0,0,0,0,0xf2,0x48,0x0f,0x2a,0
        ])))
        guest=subprocess.run([str(self.runner),str(image)],
                             capture_output=True,timeout=10)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',guest.stderr)


if __name__=='__main__':
    unittest.main()
