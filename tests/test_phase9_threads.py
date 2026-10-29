# SPDX-License-Identifier: AGPL-3.0-only
import os
import signal
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
import phase9_threads
from phase9_runtime import commands as runtime_commands
CASES=('basic','fds','fs','cond','robust','detach','cancel','kill','fork','exec','exec-failed','capacity','quota')
class ThreadGateTests(unittest.TestCase):
    def test_native_gate_requires_every_workload_challenge_digest_and_clean_exit(self):
        commit='a'*40;digests={name:'b'*64 for name in phase9_threads.NAMES}
        lines=['linux-amd64-threads-v1']+[digests[n]+'  /tmp/'+v for n,v in phase9_threads.NAMES.items()]
        start=137+len(runtime_commands(commit))
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(start,start+len(phase9_threads.commands(commit))-1)]
        result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines += ['FLEX_THREADS_BEGIN']
        for mode in phase9_threads.PTHREADS:lines += [f'FLEX_THREADS_OK {mode}',f'T_{mode}_{commit}',f'FLEX_PTHREAD_{mode}_OK',result]
        for mode in phase9_threads.RAW:lines += [f'FLEX_RAW_THREADS_OK {mode}',f'T_{mode}_{commit}',f'FLEX_RAW_{mode}_OK',result]
        lines += ['FLEX_MM_LIFETIME_OK','T_mm_'+commit,'FLEX_MM_RUN_OK',result,'FLEX_THREADS_END','FLEX_THREADS_DONE']
        serial=('\n'.join(lines)+'\n').encode()
        self.assertTrue(phase9_threads.inspect(serial,commit,digests)['passed'])
        for token in ('FLEX_THREADS_DONE','FLEX_PTHREAD_exec_OK','T_robust_'+commit,'b'*64):
            self.assertFalse(phase9_threads.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
        self.assertFalse(phase9_threads.inspect(serial.replace(b'exit=0',b'exit=1',1),commit,digests)['passed'])
        self.assertTrue(all(len(c)<220 for c in phase9_threads.commands(commit)))

@unittest.skipUnless(os.environ.get('COMPACT_MUSL_DIR'),'set COMPACT_MUSL_DIR to pinned musl fixtures')
class ThreadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);c=ROOT/'ryzova/compat/linux'
        cls.sources=[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        cls.runner=cls.directory/'runner';subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        cls.fixtures=Path(os.environ['COMPACT_MUSL_DIR']).resolve();cls.libc=cls.fixtures/'musl-libc.so';cls.fixture=cls.fixtures/'thread-fixture'
        # Fixtures are built from unmodified musl; the application source is
        # rebuilt here, so another checkout's application cannot mask changes.
        cc=cls.fixtures/'install/bin/musl-gcc'
        subprocess.run([str(cc),'-O1','-pthread','-fPIE','-pie','-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1',str(ROOT/'tests/fixtures/compact_threads.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
        for name in ('compact_mm_lifetime','compact_thread_lifetime'):
            subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/f'tests/fixtures/{name}.c'),'-o',str(cls.directory/name)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def vm(self,mode,runner=None,env=None):
        return subprocess.run([str(runner or self.runner),'-b','4194304','-x',f'/lib/ld-musl-x86_64.so.1={self.libc}','-x',f'{self.fixture}={self.fixture}',str(self.fixture),mode,'/tmp','challenge'],env=env,capture_output=True,timeout=20)
    def test_unmodified_musl_pthreads_match_linux(self):
        for mode in CASES:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                vm=self.vm(mode);self.assertEqual(vm.returncode,0,vm.stderr)
                if mode in ('capacity','quota'):
                    self.assertEqual(vm.stdout,f'FLEX_THREADS_OK {mode}\nchallenge\n'.encode());continue
                native=subprocess.run([str(self.libc),str(self.fixture),mode,directory,'challenge'],env=dict(os.environ,FLEX_TEST_NATIVE_INTERP=str(self.libc)),capture_output=True,timeout=20)
                self.assertEqual(native.returncode,0,native.stderr)
                self.assertEqual(vm.stdout,native.stdout)
                self.assertEqual(vm.stdout,f'FLEX_THREADS_OK {mode}\nchallenge\n'.encode())
    def test_raw_thread_exit_group_robust_futex_and_vfork_parent_lifetime(self):
        cases=[(self.directory/'compact_thread_lifetime',mode) for mode in ('leader-exit','exit-group','robust','futex')]+[(self.directory/'compact_mm_lifetime',None)]
        for fixture,mode in cases:
            with self.subTest(mode=mode or 'vfork-parent-lifetime'):
                args=([mode] if mode else [])+['challenge']
                vm=subprocess.run([str(self.runner),str(fixture),*args],capture_output=True,timeout=10)
                self.assertEqual(vm.returncode,0,vm.stderr)
                native=subprocess.Popen([str(fixture),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    out,err=native.communicate(timeout=10);self.assertEqual(native.returncode,0,err);self.assertEqual(vm.stdout,out)
                finally:
                    try:os.killpg(native.pid,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_stopped_interval_timer_and_clock_entropy_bounds(self):
        fixture=self.directory/'compact_thread_lifetime'
        result=subprocess.run([str(self.runner),str(fixture),'stopped-timer','challenge'],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,2,result.stderr);self.assertIn(b'status=8 ',result.stderr)
        for mode in ('clock-ceiling','entropy-quota'):
            result=subprocess.run([str(self.runner),str(fixture),mode,'challenge'],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,f'FLEX_RAW_THREADS_OK {mode}\nchallenge\n'.encode())

    def test_thread_lifetime_under_address_undefined_and_leak_checks(self):
        runner=self.directory/'asan'
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in CASES:
            with self.subTest(mode=mode):
                vm=self.vm(mode,runner=runner,env=env);self.assertEqual(vm.returncode,0,vm.stderr)
                self.assertNotIn(b'AddressSanitizer',vm.stderr)
        for fixture,args in [(self.directory/'compact_mm_lifetime',['challenge']),*[(self.directory/'compact_thread_lifetime',[mode,'challenge']) for mode in ('leader-exit','exit-group','robust','futex')]]:
            result=subprocess.run([str(runner),str(fixture),*args],env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn(b'AddressSanitizer',result.stderr)
if __name__=='__main__':unittest.main()
