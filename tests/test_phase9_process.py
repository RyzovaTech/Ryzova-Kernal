# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import os
import random
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import build, commands, inspect, FLAGS
from phase9_linux_environment import image


class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.dir=Path(cls.tmp.name)
        cls.app=cls.dir/'compiled'
        build(cls.app)
        c=ROOT/'ryzova/compat/linux'
        cls.sources=[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu')]
        cls.runner=cls.dir/'runner'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=undefined',
            '-fno-sanitize-recover=all',*cls.sources,str(c/'process_probe.c'),'-o',str(cls.runner)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_vm(self,app,*args):
        return subprocess.run([str(self.runner),str(app),*args],capture_output=True,timeout=5)

    def test_compiled_c_startup_and_memory_matches_linux(self):
        for value in ('source-challenge','unicode-සිංහල','x'*256):
            with self.subTest(value=value):
                native=subprocess.run([str(self.app),value],env={'FLEX_MODE':'test'},capture_output=True,timeout=5)
                vm=self.run_vm(self.app,value)
                self.assertEqual(native.returncode,0,native.stderr)
                self.assertEqual(vm.returncode,0,vm.stderr)
                self.assertEqual(native.stdout,vm.stdout)
                self.assertEqual(vm.stdout,b'FLEX_COMPILED_C_OK\n'+value.encode()+b'\n')
                self.assertIn(b'syscalls=13',vm.stderr)

    def test_compiler_optimization_variants(self):
        for level in ('-O0','-O2'):
            path=self.dir/('compiled-'+level[1:])
            subprocess.run(['cc',level,*FLAGS[1:],str(ROOT/'tests/fixtures/compact_process_start.S'),
                            str(ROOT/'tests/fixtures/compact_process.c'),'-o',str(path)],
                           check=True,capture_output=True)
            native=subprocess.run([str(path),'optimized'],env={'FLEX_MODE':'test'},capture_output=True,timeout=5)
            vm=self.run_vm(path,'optimized')
            self.assertEqual(native.returncode,0,native.stderr)
            self.assertEqual(vm.returncode,0,vm.stderr)
            self.assertEqual(vm.stdout,native.stdout)

    def test_argument_limits_wrong_argc_and_no_host_environment_inheritance(self):
        self.assertEqual(self.run_vm(self.app).returncode,2)
        self.assertEqual(self.run_vm(self.app,'x'*257).returncode,2)
        self.assertEqual(self.run_vm(self.app,*(['x']*16)).returncode,2)
        env=dict(os.environ,FLEX_MODE='wrong',UNRELATED_CANARY='not-a-guest-variable')
        vm=subprocess.run([str(self.runner),str(self.app),'ok'],env=env,capture_output=True,timeout=5)
        self.assertEqual(vm.returncode,0,vm.stderr)

    def test_page_permissions_and_reclamation(self):
        binary=self.dir/'memory-tests'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=undefined',
            '-fno-sanitize-recover=all',str(ROOT/'ryzova/compat/linux/memory.c'),
            str(ROOT/'tests/phase9_memory_test.c'),'-o',str(binary)],check=True,capture_output=True)
        result=subprocess.run([str(binary)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'FLEX_MEMORY_MODEL_TESTS_PASS',result.stdout)

    def test_unmapped_read_rx_write_and_unknown_instruction_fail(self):
        # movabs rax, unmapped; mov rax,[rax] / mov [rax],rbx to RX.
        for code in (b'\x48\xb8'+(0x200000).to_bytes(8,'little')+b'\x48\x8b\x00',
                     b'\x48\xb8'+(0x400100).to_bytes(8,'little')+b'\x48\x89\x18',
                     b'\x0f\x0b'):
            path=self.dir/'bad'
            path.write_bytes(image(code,b''))
            vm=self.run_vm(path,'x')
            self.assertEqual(vm.returncode,2)
            self.assertIn(b'status='+ (b'3' if code==b'\x0f\x0b' else b'2'),vm.stderr)

    def test_malformed_integer_instruction_streams_stay_bounded(self):
        rng=random.Random(0x9f04)
        for index in range(64):
            code=bytes(rng.randrange(256) for _ in range(96))
            path=self.dir/'mutated-code'
            path.write_bytes(image(code,b''))
            result=self.run_vm(path,'x')
            self.assertIn(result.returncode,(0,2),(index,result.stderr))
            self.assertNotIn(b'runtime error:',result.stderr)

    def test_evidence_requires_c_output_startup_syscalls_digest_and_exit(self):
        commit='c'*40;digest=hashlib.sha256(self.app.read_bytes()).hexdigest()
        lines=['FLEX_PROCESS_BEGIN','FLEX_COMPILED_C_OK','PC_'+commit,
               'COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=2977 syscalls=13',
               'FLEX_PROCESS_EXIT_OK','FLEX_PROCESS_END',digest+' /tmp/p-compiled','FLEX_PROCESS_DONE']
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(60,65)]
        serial=('\n'.join(lines)+'\n').encode()
        self.assertTrue(inspect(b'COMPACT_NATIVE_BUILD_OK\n',serial,commit,digest)['passed'])
        for value in (b'FLEX_COMPILED_C_OK',b'PC_'+commit.encode(),b'FLEX_PROCESS_EXIT_OK',b'syscalls=13'):
            self.assertFalse(inspect(b'COMPACT_NATIVE_BUILD_OK\n',serial.replace(value,b'missing'),commit,digest)['passed'])
        self.assertFalse(inspect(b'echo COMPACT_NATIVE_BUILD_OK\n',serial,commit,digest)['passed'])
        self.assertFalse(inspect(b'COMPACT_NATIVE_BUILD_OK\n',serial,commit,'a'*64)['passed'])
        self.assertTrue(all(len(command)<220 for command in commands(commit)))


if __name__=='__main__':
    unittest.main()
