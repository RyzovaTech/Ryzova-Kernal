# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
import phase9_runtime
import hashlib
CASES=('handler','mask','nested','restart','eintr','alternate','stop','fatal','bad-frame','realtime','no-zombie','vector','nodefer','reset','tkill','rt-quota','sleep','timer','alarm','sigwait')
class SignalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
        c=ROOT/'ryzova/compat/linux'
        cls.sources=[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_signals.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_native_runtime_gate_rejects_mutated_challenges_and_digests(self):
        commit='a'*40;digests={name:'b'*64 for name in phase9_runtime.NAMES}
        lines=['linux-amd64-runtime-v1']+[digests[n]+'  /tmp/'+v for n,v in phase9_runtime.NAMES.items()]
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(137,137+len(phase9_runtime.commands(commit))-1)]
        result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines += ['FLEX_RUNTIME_BEGIN','FLEX_TRAP_OK','FLEX_BACKGROUND_OK','FLEX_BACKGROUND_RUN_OK','R_'+commit,result]
        for mode in phase9_runtime.SIGNALS:lines += ['FLEX_SIGNALS_OK',f'S_{mode}_{commit}',f'FLEX_SIGNAL_{mode}_OK',result]
        lines += ['FLEX_DYNAMIC_OK 7 D_'+commit,'FLEX_DYNAMIC_HELLO_OK',result,'FLEX_DLOPEN_OK 29','FLEX_DYNAMIC_OPEN_OK',result,'FLEX_NEEDED_OK 29','FLEX_DYNAMIC_NEEDED_OK',result,'FLEX_MEMORY_OK','M_'+commit,'FLEX_DYNAMIC_MEMORY_OK',result,'FLEX_COMPILER_OK',result,'FLEX_COMPILED_IN_GUEST','C_'+commit,'FLEX_COMPILED_EXEC_OK',result,'FLEX_RUNTIME_END','FLEX_RUNTIME_DONE']
        serial=('\n'.join(lines)+'\n').encode()
        self.assertTrue(phase9_runtime.inspect(serial,commit,digests)['passed'])
        for token in ('FLEX_RUNTIME_DONE','FLEX_DYNAMIC_OPEN_OK','S_handler_'+commit,'b'*64):
            self.assertFalse(phase9_runtime.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
        self.assertFalse(phase9_runtime.inspect(serial.replace(b'exit=0',b'exit=1',1),commit,digests)['passed'])
        self.assertTrue(all(len(c)<220 for c in phase9_runtime.commands(commit)))

    def test_linux_differential_handlers_frames_masks_wait_and_exit(self):
        for mode in CASES:
            with self.subTest(mode=mode):
                vm=subprocess.run([str(self.runner),str(self.fixture),mode,'challenge'],capture_output=True,timeout=10)
                self.assertEqual(vm.returncode,0,vm.stderr)
                if mode=='rt-quota':
                    self.assertEqual(vm.stdout,b'FLEX_SIGNALS_OK\nchallenge\n');continue
                native=subprocess.run([str(self.fixture),mode,'challenge'],capture_output=True,timeout=10)
                self.assertEqual(native.returncode,0,native.stderr)
                self.assertEqual(vm.stdout,native.stdout)
                self.assertEqual(vm.stdout,b'FLEX_SIGNALS_OK\nchallenge\n')
    def test_address_and_undefined_sanitizers(self):
        runner=self.directory/'asan-runner'
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in CASES:
            with self.subTest(mode=mode):
                r=subprocess.run([str(runner),str(self.fixture),mode,'challenge'],env=env,capture_output=True,timeout=10)
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertNotIn(b'AddressSanitizer',r.stderr)
if __name__=='__main__':unittest.main()
