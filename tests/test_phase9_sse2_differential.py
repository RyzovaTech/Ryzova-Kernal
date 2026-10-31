# SPDX-License-Identifier: AGPL-3.0-only
"""Host Linux vs original Ryzova C-interpreter differential SSE2 tests.

Compile unmodified AMD64 assembly with the ordinary binutils assembler;
compare the same ELF and byte-for-byte stdout under Linux and the bounded
Ryzova user-space VM, never shortcut through host execution inside the VM.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(n+'.c') for n in (
    'elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe'
)]

ASSEMBLY=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0, XMMWORD PTR [rip + initial]
    movhps xmm0, QWORD PTR [rip + upper]
    movhps QWORD PTR [rip + upper_out], xmm0
    movdqu xmm1, XMMWORD PTR [rip + initial]
    movlhps xmm1, xmm0
    movdqu xmm2, XMMWORD PTR [rip + initial]
    psrldq xmm2, 8
    pslldq xmm2, 3
    por xmm2, xmm1
    por xmm2, XMMWORD PTR [rip + other]
    movdqu XMMWORD PTR [rip + result], xmm2
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + upper_out]
    mov edx, 8
    syscall
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + result]
    mov edx, 16
    syscall
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
initial: .byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
upper:   .byte 0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80
.balign 16
other:   .byte 0x80,0x40,0x20,0x10,0,0,0,0,0,0,0,0,0,0,0,0
upper_out: .zero 8
result: .zero 16
"""


class Sse2DifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.runner=cls.root/'runner'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       check=True,capture_output=True,timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_exact_movhps_movlhps_psrldq_pslldq_por_differential(self):
        source=self.root/'sse.S'
        binary=self.root/'sse'
        source.write_text(ASSEMBLY)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        self.assertEqual(len(guest.stdout),24)
        self.assertEqual(guest.stdout[:8],bytes([0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80]))
        # MOVLHPS retained xmm1 low bytes, copied xmm0 low into its high.
        # POR with memory sets bit 7/6/5/4 of first four output bytes.
        base=bytearray(range(16))
        base[8:16]=range(8)
        shifted=bytearray(16)
        shifted[:8]=range(8,16)
        moved=bytearray(16)
        moved[3:11]=shifted[:8]
        expected=bytes(moved[i] | base[i] | ([0x80,0x40,0x20,0x10][i] if i<4 else 0)
                       for i in range(16))
        self.assertEqual(guest.stdout[8:],expected)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_punpckldq_register_memory_and_alias_linux_differential(self):
        # CPython 3.12.10 diagnostics: 66 0F 62 C2. Compare real
        # Linux and the same ELF in the Ryzova instruction interpreter.
        asm=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0, XMMWORD PTR [rip + left]
    movdqu xmm1, XMMWORD PTR [rip + right]
    punpckldq xmm0, xmm1
    movdqu XMMWORD PTR [rip + out0], xmm0
    movdqu xmm2, XMMWORD PTR [rip + second]
    punpckldq xmm2, XMMWORD PTR [rip + aligned]
    movdqu XMMWORD PTR [rip + out1], xmm2
    movdqu xmm3, XMMWORD PTR [rip + left]
    punpckldq xmm3, xmm3
    movdqu XMMWORD PTR [rip + out2], xmm3
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + out0]
    mov edx, 48
    syscall
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
left: .byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
right: .byte 128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143
second: .byte 240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
aligned: .byte 160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175
out0: .zero 16
out1: .zero 16
out2: .zero 16
"""
        source=self.root/'unpack.S'
        binary=self.root/'unpack'
        source.write_text(asm)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        self.assertEqual(guest.stdout,
                         bytes([0,1,2,3,128,129,130,131,4,5,6,7,132,133,134,135,
                                240,241,242,243,160,161,162,163,244,245,246,247,164,165,166,167,
                                0,1,2,3,0,1,2,3,4,5,6,7,4,5,6,7]))
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_cvtsi2ss_integer_precision_sign_rounding_and_upper_xmm(self):
        # Genuine CPython -c failure: F3 48 0F 2A C1. Test strict default
        # RN-even rounding at 24-bit precision and signed 32/64 conversion.
        asm=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0, XMMWORD PTR [rip + sentinel]
    mov rcx, 16777217
    cvtsi2ss xmm0, rcx
    movdqu XMMWORD PTR [rip + out0], xmm0
    movdqu xmm1, XMMWORD PTR [rip + sentinel]
    mov ecx, -16777217
    cvtsi2ss xmm1, ecx
    movdqu XMMWORD PTR [rip + out1], xmm1
    movdqu xmm2, XMMWORD PTR [rip + sentinel]
    mov rcx, 0x7fffffffffffffff
    cvtsi2ss xmm2, rcx
    movdqu XMMWORD PTR [rip + out2], xmm2
    movdqu xmm3, XMMWORD PTR [rip + sentinel]
    mov rcx, 0x8000000000000000
    cvtsi2ss xmm3, rcx
    movdqu XMMWORD PTR [rip + out3], xmm3
    movdqu xmm4, XMMWORD PTR [rip + sentinel]
    cvtsi2ss xmm4, DWORD PTR [rip + unaligned]
    movdqu XMMWORD PTR [rip + out4], xmm4
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + out0]
    mov edx, 80
    syscall
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
sentinel: .byte 160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175
out0: .zero 16
out1: .zero 16
out2: .zero 16
out3: .zero 16
out4: .zero 16
unaligned_pad: .byte 55
unaligned: .long -42
"""
        source=self.root/'cvtsi2ss.S'
        binary=self.root/'cvtsi2ss'
        source.write_text(asm)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       check=True,capture_output=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        import struct
        vals=[16777216.,-16777216.,float(2**63),-float(2**63),-42.]
        sentinel=bytes(range(160,176))
        expected=b''.join(struct.pack('<f',v)+sentinel[4:] for v in vals)
        self.assertEqual(guest.stdout,expected)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_comiss_flag_results_float_order_unordered_and_signed_zero(self):
        # Frozen CPython -c next candidate: 0F 2F /r COMISS. Native Linux
        # and Ryzova guest must agree on exact CF/PF/ZF/AF/SF/OF bits.
        cases=[
            (0x3f800000,0x40000000,0x001,'reg'), # 1 < 2
            (0x40000000,0x3f800000,0x000,'reg'), # 2 > 1
            (0x80000000,0x00000000,0x040,'reg'), # -0 == +0
            (0x7fc00000,0x3f800000,0x045,'reg'), # unordered quiet NaN
            (0xc0000000,0xbf800000,0x001,'reg'), # -2 < -1
            (0xbf800000,0xc0000000,0x000,'reg'), # -1 > -2
            (0x7f800000,0x7f7fffff,0x000,'reg'), # +inf > max
            (0xff800000,0xff800000,0x040,'reg'), # -inf == -inf
            (0x00000001,0x00000000,0x000,'memory'), # subnormal > 0
            (0x80000001,0x00000000,0x001,'memory'), # negative subnormal < 0
        ]
        asm=['.intel_syntax noprefix','.section .text',
             '.global _start','_start:']
        for i,(_,__,___,kind) in enumerate(cases):
            asm.extend([
                f'movdqu xmm0, XMMWORD PTR [rip + left{i}]',
                f'movdqu xmm1, XMMWORD PTR [rip + right{i}]',
                f'comiss xmm0, '+(
                    f'DWORD PTR [rip + right{i}]' if kind=='memory' else 'xmm1'),
                'pushfq','pop rax','and eax, 0x8d5',
                f'mov QWORD PTR [rip + out{i}], rax',
            ])
        asm.extend(['mov eax,1','mov edi,1','lea rsi,[rip + out0]',
                    f'mov edx,{8*len(cases)}','syscall',
                    'mov eax,60','xor edi,edi','syscall',
                    '.section .data','.balign 16'])
        for i in range(len(cases)):
            asm.append(f'out{i}: .zero 8')
        for i,(left,right,_,__) in enumerate(cases):
            for label,value in ((f'left{i}',left),(f'right{i}',right)):
                asm.append(f'{label}: .long {value}')
                asm.append('  .byte '+','.join(str(x) for x in range(160,172)))
        source=self.root/'comiss.S'
        binary=self.root/'comiss'
        source.write_text('\n'.join(asm)+'\n')
        subprocess.run(['cc','-nostdlib','-static','-no-pie',
                        str(source),'-o',str(binary)],
                       check=True,capture_output=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        import struct
        want=b''.join(struct.pack('<Q',expected) for _,__,expected,___ in cases)
        self.assertEqual(guest.stdout,want)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_ucomiss_remains_unsupported_without_false_acceptance(self):
        from test_phase9_image_admission import executable
        bad=self.root/'unsupported-ucomiss.elf'
        bad.write_bytes(executable(code=bytes([0x0f,0x2e,0xc1])))
        out=subprocess.run([str(self.runner),str(bad)],
                           capture_output=True,timeout=15)
        self.assertEqual(out.returncode,2,out.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',out.stderr)

    def test_divss_scalar_ieee754_linux_differential(self):
        # CPython -c candidate F3 0F 5E C1. Preserve full destination XMM
        # upper 96 bits; test exact default round-to-nearest-even results.
        cases=[
            (0x40e00000,0x40000000,0x40600000,'register'),  # 7 / 2 = 3.5
            (0x00000003,0x40000000,0x00000002,'memory'),    # subnormal tie-even
            (0x40e00000,0x00000000,0x7f800000,'register'),  # +infinity
            (0xc0e00000,0x40000000,0xc0600000,'register'),  # -7 / 2
            (0x00800000,0x40000000,0x00400000,'memory'),    # min-normal / 2
            (0x00000001,0x40000000,0x00000000,'register'),  # underflow tie-even
            (0x80000000,0x40000000,0x80000000,'register'),  # signed zero
            (0x7f7fffff,0x00800000,0x7f800000,'register'),  # overflow
        ]
        asm=['.intel_syntax noprefix','.section .text','.global _start','_start:']
        for i,(_,__,___,kind) in enumerate(cases):
            asm += [f'movdqu xmm0, XMMWORD PTR [rip + left{i}]',
                    f'movdqu xmm1, XMMWORD PTR [rip + right{i}]',
                    (f'divss xmm0, DWORD PTR [rip + right{i}]'
                     if kind=='memory' else 'divss xmm0, xmm1'),
                    f'movdqu XMMWORD PTR [rip + out{i}], xmm0']
        asm += ['mov eax, 1','mov edi, 1','lea rsi, [rip + out0]',
                f'mov edx, {16*len(cases)}','syscall','mov eax, 60',
                'xor edi, edi','syscall','.section .data','.balign 16']
        for i in range(len(cases)):
            asm += [f'out{i}: .zero 16']
        for i,(left,right,_,__) in enumerate(cases):
            for label,value in ((f'left{i}',left),(f'right{i}',right)):
                asm += [f'{label}: .long {value}', '  .byte '+','.join(
                    str(x) for x in range(160,172))]
        source=self.root/'divss.S'
        binary=self.root/'divss'
        source.write_text('\n'.join(asm)+'\n')
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        import struct
        expected=b''.join(struct.pack('<I',word)+bytes(range(160,172))
                          for _,__,word,___ in cases)
        self.assertEqual(guest.stdout,expected)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_unimplemented_double_divsd_stays_explicitly_denied(self):
        from test_phase9_image_admission import executable
        bad=self.root/'unsupported-divsd.elf'
        bad.write_bytes(executable(code=bytes([0xf2,0x0f,0x5e,0xc1])))
        out=subprocess.run([str(self.runner),str(bad)],
                           capture_output=True,timeout=15)
        self.assertEqual(out.returncode,2,out.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',out.stderr)

    def test_unimplemented_scalar_double_form_still_fails_closed(self):
        from test_phase9_image_admission import executable
        bad=self.root/'unsupported-cvtsi2sd.elf'
        bad.write_bytes(executable(code=bytes([0xf2,0x48,0x0f,0x2a,0xc1])))
        actual=subprocess.run([str(self.runner),str(bad)],
                              capture_output=True,timeout=15)
        self.assertEqual(actual.returncode,2,actual.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',actual.stderr)

    def test_pshufd_register_memory_and_self_alias_linux_differential(self):
        # CPython 3.12.10 now reaches 66 0F 70 E8 E5.
        asm=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm1, XMMWORD PTR [rip + src0]
    pshufd xmm0, xmm1, 0xe5
    movdqu XMMWORD PTR [rip + out0], xmm0
    pshufd xmm2, XMMWORD PTR [rip + src1], 0x1b
    movdqu XMMWORD PTR [rip + out1], xmm2
    movdqu xmm3, XMMWORD PTR [rip + src0]
    pshufd xmm3, xmm3, 0x00
    movdqu XMMWORD PTR [rip + out2], xmm3
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + out0]
    mov edx, 48
    syscall
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
src0: .byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
src1: .byte 128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143
out0: .zero 16
out1: .zero 16
out2: .zero 16
"""
        source=self.root/'pshufd.S'
        binary=self.root/'pshufd'
        source.write_text(asm)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        expect=(bytes([4,5,6,7,4,5,6,7,8,9,10,11,12,13,14,15])+
                bytes([140,141,142,143,136,137,138,139,132,133,134,135,128,129,130,131])+
                bytes([0,1,2,3]*4))
        self.assertEqual(guest.stdout,expect)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_pshufd_misaligned_memory_denied_like_linux(self):
        asm=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    pshufd xmm0, XMMWORD PTR [rip + unaligned], 0x1b
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
misalign_pad: .byte 3
unaligned: .zero 16
"""
        source=self.root/'pshufd-bad.S'
        binary=self.root/'pshufd-bad'
        source.write_text(asm)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,-11,native.stderr)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',guest.stderr)

    def test_punpckldq_unaligned_memory_denied_like_linux(self):
        asm=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    movdqu xmm0, XMMWORD PTR [rip + left]
    punpckldq xmm0, XMMWORD PTR [rip + unaligned]
    mov eax, 60
    xor edi, edi
    syscall
.section .data
.balign 16
left: .zero 16
unaligned_pad: .byte 7
unaligned: .zero 16
"""
        source=self.root/'unpack-bad.S'
        binary=self.root/'unpack-bad'
        source.write_text(asm)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,-11,native.stderr)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',guest.stderr)

    def test_misaligned_legacy_por_memory_fails_closed(self):
        # Legacy POR's 128-bit memory operand requires 16-byte alignment.
        # Confirm real Linux SIGSEGV and bounded VM map failure separately.
        source=self.root/'por-bad.S'
        binary=self.root/'por-bad'
        source.write_text(ASSEMBLY.replace(
            '.balign 16\\nother:', 'other:').replace(
            '.balign 16\nother:', 'other:'))
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=25)
        self.assertEqual(native.returncode,-11)
        self.assertEqual(guest.returncode,2,guest.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=2',guest.stderr)

    def test_getrusage_self_returns_bounded_virtual_abi_without_host_forward(self):
        # A source-built Linux AMD64 ELF probes getrusage(98). Compare the
        # positive call plus EINVAL and EFAULT negative paths on real Linux
        # and on the user-space Ryzova guest. Do not compare physical CPU
        # timing/RSS against explicitly virtual instruction-time estimates.
        assembly=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    mov eax, 98
    xor edi, edi
    lea rsi, [rip + usage]
    syscall
    test eax, eax
    jne fail
    mov rax, QWORD PTR [rip + usage + 8]
    cmp rax, 1000000
    jae fail
    mov eax, 98
    mov edi, 99
    lea rsi, [rip + usage]
    syscall
    cmp rax, -22
    jne fail
    mov eax, 98
    xor edi, edi
    xor esi, esi
    syscall
    cmp rax, -14
    jne fail
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + success]
    mov edx, 19
    syscall
    mov eax, 60
    xor edi, edi
    syscall
fail:
    mov eax, 60
    mov edi, 22
    syscall
.section .data
usage: .zero 144
success: .ascii "RUSAGE_VIRTUAL_OK!\n"
"""
        source=self.root/'rusage.S'
        binary=self.root/'rusage'
        source.write_text(assembly)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        native=subprocess.run([str(binary)],capture_output=True,timeout=5)
        guest=subprocess.run([str(self.runner),str(binary)],capture_output=True,timeout=20)
        self.assertEqual(native.returncode,0,native.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(guest.stdout,native.stdout)
        self.assertEqual(guest.stdout,b'RUSAGE_VIRTUAL_OK!\n')
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_unsupported_sse2_subencoding_fails_explicitly(self):
        # 66 0F73 /2 imm8 is a different instruction family, not
        # supported by the intentionally finite CLX-04 subset.
        from test_phase9_image_admission import executable
        bad=self.root/'unimplemented.sse'
        bad.write_bytes(executable(code=bytes([0x66,0x0f,0x73,0xd1,0x08])))
        actual=subprocess.run([str(self.runner),str(bad)],capture_output=True,timeout=15)
        self.assertEqual(actual.returncode,2,actual.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=3',actual.stderr)

if __name__=='__main__':
    unittest.main()
