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


def executable(*,pie=False,mapped=4096,interpreter=None):
    """File-offset-aligned real AMD64 ELF64 with a bounded synthetic PT_LOAD."""
    if mapped < 4096 or mapped > 8*1024*1024:
        raise ValueError("test fixture memory span must remain bounded")
    raw=bytearray(0x1200)
    raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI',raw,16,3 if pie else 2,62,1)
    struct.pack_into('<QQ',raw,24,0x1000 if pie else 0x401000,64)
    struct.pack_into('<HHH',raw,52,64,56,2 if interpreter else 1)
    vaddr=0x1000 if pie else 0x401000
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0x1000,vaddr,0,0x200,mapped,0x1000)
    raw[0x1000:0x1000+len(EXIT0)]=EXIT0
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
