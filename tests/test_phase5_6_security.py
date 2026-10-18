# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic hostile input tests for all three parser paths (host-only)."""
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))
from test_phase5_elf import fixture as elf_fixture
from test_phase5_5_pe import fixture as pe_fixture
from test_phase5_7_macho import fixture as macho_fixture

class Phase56Security(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.dir=Path(cls.temp.name)
        cc=os.environ.get("PHASE5_CC","cc")
        flags=["-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            flags+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        cls.tools={}
        for label,files in {
          "elf":["ryzova/compat/linux/elf64.c","ryzova/compat/linux/elf64_probe.c"],
          "pe":["ryzova/compat/windows/pe64.c","ryzova/compat/windows/pe64_probe.c"],
          "macho":["ryzova/compat/macos/macho64.c","ryzova/compat/macos/macho64_probe.c"],
          "namespace":["ryzova/compat/linux/namespace.c","tests/phase5_namespace_fuzz.c"],
        }.items():
            exe=str(cls.dir/label)
            proc=subprocess.run([cc,*flags,*(str(ROOT/f) for f in files),"-o",exe],
                capture_output=True,text=True)
            if proc.returncode:
                raise AssertionError(label+" compiler error:\n"+proc.stderr)
            cls.tools[label]=exe
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def mutate(self,label,seed,iterations,span):
        rng=random.Random(seed)
        originals={"elf":elf_fixture(),"pe":pe_fixture(),"macho":macho_fixture()}
        original=originals[label]
        file=self.dir/("candidate."+label)
        for i in range(iterations):
            data=bytearray(original)
            if i%11==0:
                data=data[:rng.randrange(len(data))]
            else:
                for _ in range(rng.randrange(1,10)):
                    if not data:break
                    pos=rng.randrange(min(len(data),span))
                    data[pos]=rng.randrange(256)
            file.write_bytes(data)
            cmd=[self.tools[label],str(file)]
            if label=="elf":cmd.append("--materialize")
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=5)
            self.assertIn(p.returncode,(0,2),f"{label} mutation={i}: {p.stderr} {p.stdout}")
            self.assertNotIn("runtime error:",p.stderr.lower())
    def test_elf64_adversarial_mutations(self):
        self.mutate("elf",0x5100,100,170)
    def test_pe32plus_adversarial_mutations(self):
        self.mutate("pe",0x5500,100,440)
    def test_macho64_adversarial_mutations(self):
        self.mutate("macho",0x5700,100,180)
    def test_virtual_namespace_random_paths(self):
        p=subprocess.run([self.tools["namespace"]],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn("PHASE5_6_NAMESPACE_FUZZ_PASS 10000",p.stdout)
if __name__=="__main__":unittest.main()
