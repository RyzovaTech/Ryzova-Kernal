# SPDX-License-Identifier: AGPL-3.0-only
"""Execute actual Clang/LLD Windows ARM64 PE machine-code in Ryzova's finite VM.

The host used for CI is AMD64. This is NOT proof of native ARM64 kernel boot,
physical ARM64 hardware, general Windows support, Win32 imports or ARM64EC.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"ryzova/compat/windows"
FIXTURE=ROOT/"tests/fixtures/windows_w7_arm64_reference.c"
PAT=re.compile(r"CW_ARM64_RESULT status=(\d+) exit=(\d+) steps=(\d+) pc=([0-9a-f]+) insn=([0-9a-f]+)")
def u16(b,i):return int.from_bytes(b[i:i+2],"little")
def u32(b,i):return int.from_bytes(b[i:i+4],"little")
def mutant(b,i,value,n=4):
    out=bytearray(b);out[i:i+n]=value.to_bytes(n,"little");return bytes(out)

class RealWindowsArm64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.d=Path(cls.tmp.name)
        cc,clang,linker=(shutil.which(x) for x in ("cc","clang","lld-link"))
        if not cc or not clang or not linker:
            raise AssertionError("real C compiler, Windows-target clang and lld-link are mandatory")
        cls.runner=cls.d/"cw-arm64"
        subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Werror","-O2",
                        str(SRC/"arm64_probe.c"),str(SRC/"arm64_probe_main.c"),
                        "-o",str(cls.runner)],check=True,capture_output=True,timeout=45)
        cls.real={}
        for optimize in ("O0","O2"):
            obj=cls.d/(optimize+".obj");pe=cls.d/(optimize+".exe")
            subprocess.run([clang,"--target=aarch64-windows-msvc",
                            "-"+optimize,"-c",str(FIXTURE),"-o",str(obj)],
                           check=True,capture_output=True,timeout=30)
            subprocess.run([linker,"/machine:arm64","/entry:main",
                            "/subsystem:console","/nodefaultlib",
                            "/out:"+str(pe),str(obj)],
                           check=True,capture_output=True,timeout=30)
            cls.real[optimize]=pe.read_bytes()
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def run_pe(self,bytes_):
        pe=self.d/"candidate.exe";pe.write_bytes(bytes_)
        run=subprocess.run([str(self.runner),str(pe)],capture_output=True,timeout=15)
        m=PAT.fullmatch(run.stdout.decode("ascii","replace").strip())
        self.assertIsNotNone(m,(run.returncode,run.stdout,run.stderr))
        return (run.returncode,int(m[1]),int(m[2]),int(m[3]))

    def test_both_real_compiler_optimization_profiles(self):
        for mode,exe in self.real.items():
            with self.subTest(mode=mode):
                p=u32(exe,0x3c)
                self.assertEqual(u16(exe,p+4),0xaa64)
                self.assertEqual(u16(exe,p+24),0x20b)
                self.assertEqual(self.run_pe(exe)[:3],(0,0,37))
        self.assertGreater(self.run_pe(self.real["O0"])[3],
                           self.run_pe(self.real["O2"])[3])

    def test_architecture_import_and_tls_denials(self):
        b=self.real["O0"];p=u32(b,0x3c);op=p+24
        for value in (0x8664,0xa641,0xa64e,0x14c,0):
            with self.subTest(machine=value):
                self.assertEqual(self.run_pe(mutant(b,p+4,value,2)),(2,1,0,0))
        for index in (1,2,5,9,14):
            with self.subTest(directory=index):
                self.assertEqual(self.run_pe(mutant(b,op+112+8*index,0x1000)),
                                 (2,1,0,0))

    def test_structural_bounds_wx_and_overlap_fail_closed(self):
        b=self.real["O0"];p=u32(b,0x3c);op=p+24
        sec=op+u16(b,p+20)
        bad=[b[:150],b"BAD",mutant(b,0x3c,0xfffffff0),
             mutant(b,p+6,9,2),mutant(b,op+16,0x1002),
             mutant(b,op+60,0xffffffff),mutant(b,sec+36,0xe0000020),
             mutant(b,sec+20,0xffffffff),mutant(b,sec+12,0xfff00000),
             mutant(b,op+32,1234)]
        if u16(b,p+6)>1:
            other=sec+40
            bad.append(mutant(b,other+20,u32(b,sec+20)))
            bad.append(mutant(b,other+12,u32(b,sec+12)))
        for i,case in enumerate(bad):
            with self.subTest(mutation=i):
                self.assertEqual(self.run_pe(case),(2,1,0,0))

    def test_svc_illegal_loop_and_branch_rejected(self):
        b=self.real["O2"];p=u32(b,0x3c)
        sec=p+24+u16(b,p+20)
        self.assertEqual(u32(b,p+24+16),u32(b,sec+12))
        start=u32(b,sec+20)
        for insn,status in ((0xd4000001,2),(0xffffffff,2),
                            (0x14000000,4),(0x1400ffff,3)):
            with self.subTest(opcode=hex(insn)):
                result=self.run_pe(mutant(b,start,insn))
                self.assertEqual(result[1],status)
                self.assertNotEqual(result[0],0)
                if status==4:self.assertEqual(result[3],4096)

if __name__=="__main__":unittest.main()
