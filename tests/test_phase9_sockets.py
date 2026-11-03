# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
import phase9_sockets as net
class SocketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
        cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_sockets.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def vm(self,mode,runner=None,env=None):return subprocess.run([str(runner or self.runner),str(self.fixture),mode,'challenge'],env=env,capture_output=True,timeout=10)
    def native(self,mode):
        process=subprocess.Popen([str(self.fixture),mode,'challenge'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            out,err=process.communicate(timeout=10);self.assertEqual(process.returncode,0,err);return out
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
    def test_linux_differential_streams_http_primitives_and_byte_order(self):
        for mode in net.DIFFERENTIAL:
            with self.subTest(mode=mode):
                vm=self.vm(mode);self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,self.native(mode))
    @unittest.skipIf(os.environ.get('COMPACT_DISABLE_NATIVE_UNIX_BIND')=='1','host sandbox denies Unix bind; guest Unix test still runs below')
    def test_linux_differential_abstract_unix_bind(self):
        vm=self.vm('unix');self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,self.native('unix'))
    def test_explicit_bounds_namespaces_error_pointers_and_resource_reclamation(self):
        for mode in net.CASES:
            with self.subTest(mode=mode):
                vm=self.vm(mode);self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,f'FLEX_SOCKETS_OK {mode}\nchallenge\n'.encode())
    def test_address_undefined_and_leak_checks(self):
        runner=self.directory/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in net.CASES:
            with self.subTest(mode=mode):
                vm=self.vm(mode,runner,env);self.assertEqual(vm.returncode,0,vm.stderr);self.assertNotIn(b'AddressSanitizer',vm.stderr)
    @unittest.skipUnless(os.environ.get('COMPACT_MUSL_DIR'),'set COMPACT_MUSL_DIR to pinned musl fixtures')
    def test_musl_pthread_http_request_response_and_eof_match_linux(self):
        cache=Path(os.environ['COMPACT_MUSL_DIR']).resolve();image=self.directory/'http'
        subprocess.run([str(cache/'install/bin/musl-gcc'),'-O1','-pthread','-fPIE','-pie','-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1',str(ROOT/'tests/fixtures/compact_socket_http.c'),'-o',str(image)],check=True,capture_output=True)
        vm=subprocess.run([str(self.runner),'-b','4194304','-x',f'/lib/ld-musl-x86_64.so.1={cache/"musl-libc.so"}',str(image),'challenge'],capture_output=True,timeout=10)
        native=subprocess.run([str(cache/'musl-libc.so'),str(image),'challenge'],capture_output=True,timeout=10)
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout);self.assertEqual(vm.stdout,b'FLEX_SOCKET_HTTP_OK\nchallenge\n')
    def test_native_gate_rejects_missing_challenges_digests_and_nonzero_exits(self):
        commit='a'*40;digests={name:'b'*64 for name in net.NAMES};result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines=['linux-amd64-local-sockets-v1']+[digests[n]+'  /tmp/'+v for n,v in net.NAMES.items()]
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(net.start(commit),net.start(commit)+len(net.commands(commit))-1)]+['FLEX_SOCKETS_BEGIN']
        for mode in net.CASES:lines += [f'FLEX_SOCKETS_OK {mode}',f'N_{mode}_{commit}',f'FLEX_SOCKET_{mode}_OK',result]
        lines += ['FLEX_SOCKET_HTTP_OK','H_'+commit,'FLEX_HTTP_RUN_OK',result,'FLEX_SOCKETS_END','FLEX_SOCKETS_DONE'];serial=('\n'.join(lines)+'\n').encode()
        self.assertTrue(net.inspect(serial,commit,digests)['passed'])
        for token in ('FLEX_SOCKETS_DONE','FLEX_HTTP_RUN_OK','N_unix_'+commit,'b'*64):self.assertFalse(net.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
        self.assertFalse(net.inspect(serial.replace(b'exit=0',b'exit=1',1),commit,digests)['passed']);self.assertTrue(all(len(c)<220 for c in net.commands(commit)))
if __name__=='__main__':unittest.main()
