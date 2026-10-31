# SPDX-License-Identifier: AGPL-3.0-only
"""Real bounded AMD64 guest tests for measured ELF buffers and PIE loader layout.

Linux host runs the exact Ryzova C interpreter, NOT native-QEMU or release proof.
"""
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
EXIT0=b'\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05'
SOURCES=[CORE/(x+'.c') for x in
         ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]


def executable(*,pie=False,mapped=8192,interpreter=None,code=EXIT0):
    """File-offset-aligned real AMD64 ELF64 with a bounded synthetic PT_LOAD."""
    if mapped < 8192 or mapped > 8*1024*1024:
        raise ValueError("test fixture memory span must remain bounded")
    raw=bytearray(0x1200)
    raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI',raw,16,3 if pie else 2,62,1)
    struct.pack_into('<QQ',raw,24,0x1000 if pie else 0x401000,64)
    struct.pack_into('<HHH',raw,52,64,56,2 if interpreter else 1)
    # Real PT_LOAD must include ELF header and PT_PHDR bytes: the Ryzova
    # loader validates AT_PHDR against a mapped, readable segment.
    vaddr=0 if pie else 0x400000
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,vaddr,0,0x1200,mapped,0x1000)
    if not 1 <= len(code) <= 256:
        raise ValueError('bounded guest test code only')
    raw[0x1000:0x1000+len(code)]=code
    if interpreter:
        filename=interpreter.encode('ascii')+b'\0'
        if len(filename)>128:
            raise ValueError("excessively long test interpreter")
        raw[0x1100:0x1100+len(filename)]=filename
        struct.pack_into('<IIQQQQQQ',raw,120,3,4,0x1100,0,0,len(filename),len(filename),1)
    return bytes(raw)


class ImageAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.d=Path(cls.tmp.name)
        cls.runner=cls.d/'jobs_probe'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       check=True,capture_output=True,timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def invoke(self,*args):
        return subprocess.run([str(self.runner),*map(str,args)],
                              capture_output=True,timeout=25)

    def test_measured_python_image_28mb_is_admitted_without_unlimited_memory(self):
        # Measured pinned CPython 3.12.10 executable is 27,726,864 bytes.
        # Synthetic *small LOAD* with the same image file size checks bounded
        # admission independently of unsupported Python ISA/stdlib semantics.
        file=self.d/'large-elf'
        with file.open('wb') as stream:
            stream.write(executable())
            stream.truncate(27_726_864)
        out=self.invoke(file)
        self.assertEqual(out.returncode,0,out.stderr[-2500:])
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',out.stderr)

    def test_over_per_image_ceiling_rejected_before_loading(self):
        file=self.d/'oversized-elf'
        with file.open('wb') as stream:
            stream.write(executable())
            stream.truncate(32*1024*1024+1)
        self.assertEqual(self.invoke(file).returncode,65)

    def test_aggregate_grant_budget_rejected_before_loading(self):
        file=self.d/'large-elf'
        with file.open('wb') as stream:
            stream.write(executable())
            stream.truncate(27_726_864)
        # Main 27.7 MB + separately buffered explicit grant 27.7 MB exceeds
        # the measured bounded 48-MiB combined image-buffer ceiling.
        grant='/lib/extra.so='+str(file)
        self.assertEqual(self.invoke('-x',grant,file).returncode,65)

    def test_large_pie_and_musl_interpreter_do_not_overlap(self):
        # Main LOAD covers 6 MiB starting at PIE bias 0x400000, so the old
        # fixed 0x800000 interpreter bias overlaps its mapped virtual span.
        interp='/lib/ld-musl-x86_64.so.1'
        main=self.d/'large-pie'
        ld=self.d/'small-interpreter'
        main.write_bytes(executable(pie=True,mapped=6*1024*1024,interpreter=interp))
        ld.write_bytes(executable(pie=True))
        out=self.invoke('-x',interp+'='+str(ld),main)
        self.assertEqual(out.returncode,0,out.stderr[-2500:])
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',out.stderr)

    def test_unknown_guest_syscall_reports_number_and_fails_closed(self):
        # mov eax,999; syscall — no corresponding allowed Linux syscall.
        image=self.d/'unsupported-syscall'
        image.write_bytes(executable(code=bytes([0xb8,0xe7,0x03,0,0,0x0f,0x05])))
        out=self.invoke(image)
        self.assertEqual(out.returncode,2,out.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=5',out.stderr)
        self.assertIn(b'unsupported_syscall=999 unsupported_syscall_valid=1',out.stderr)

    def test_executable_grant_lseek_tracks_measured_image_ceiling(self):
        # A 6-MiB explicitly granted image must be seekable/readable beyond
        # the old 4-MiB cap, without extending the 32-MiB finite ABI bound.
        large=self.d/'large-grant-image'
        with large.open('wb') as stream:
            stream.write(executable())
            stream.truncate(6*1024*1024)
        asm=r"""
.intel_syntax noprefix
.section .text
.global _start
_start:
    mov eax, 2
    lea rdi, [rip + resource]
    xor esi, esi
    syscall
    test eax, eax
    js fail
    mov ebx, eax
    mov edi, ebx
    mov eax, 8
    mov esi, 5242880
    xor edx, edx
    syscall
    cmp rax, 5242880
    jne fail
    mov edi, ebx
    mov eax, 8
    mov esi, 33554433
    xor edx, edx
    syscall
    cmp rax, -22
    jne fail
    mov eax, 60
    xor edi, edi
    syscall
fail:
    mov eax, 60
    mov edi, 51
    syscall
.section .rodata
resource: .asciz "/lib/large-grant.so"
"""
        source=self.d/'lseek-elf.S'
        binary=self.d/'lseek-elf'
        source.write_text(asm)
        subprocess.run(['cc','-nostdlib','-static','-no-pie',str(source),'-o',str(binary)],
                       capture_output=True,check=True,timeout=30)
        out=self.invoke('-x','/lib/large-grant.so='+str(large),binary)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',out.stderr)

    def test_budgets_match_host_profile_configuration(self):
        from importlib.util import spec_from_file_location,module_from_spec
        path=ROOT/'scripts/compact_linux_target_profiles.py'
        spec=spec_from_file_location('target_profiles_image_budget',path)
        module=module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.IMAGE_MAX_BYTES,32*1024*1024)
        self.assertEqual(module.IMAGE_TOTAL_BYTES,48*1024*1024)
        h=(CORE/'process.h').read_text()
        self.assertIn('#define RYZ_PROCESS_IMAGE_MAX (32U * 1024U * 1024U)',h)
        self.assertIn('#define RYZ_PROCESS_IMAGE_TOTAL_MAX (48U * 1024U * 1024U)',h)


if __name__=='__main__':
    unittest.main()
