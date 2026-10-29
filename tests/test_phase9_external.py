# SPDX-License-Identifier: AGPL-3.0-only
import http.server
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
import phase9_external as gate

class ExternalGateTests(unittest.TestCase):
    def test_native_gate_requires_http_observations_every_challenge_and_no_grant_denial(self):
        commit='a'*40;digest='b'*64;result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines=['linux-amd64-tcp-resources-v1',digest+'  /tmp/ex-http',digest+'  /tmp/ex-hosts']+[f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]+['FLEX_EXTERNAL_BEGIN']
        for mode in gate.CASES:lines += ['FLEX_EXTERNAL_OK '+mode,'E_'+mode+'_'+commit,result,'FLEX_EXTERNAL_'+mode+'_RUN_OK']
        lines += ['FLEX_EXTERNAL_SOURCE_'+commit,result,'FLEX_EXTERNAL_WGET_OK',result,'FLEX_EXTERNAL_WGET_SAVE_OK','FLEX_EXTERNAL_SOURCE_'+commit,result,'FLEX_EXTERNAL_WGET_RELOAD_OK','FLEX_EXTERNAL_SOURCE_'+commit,result,'FLEX_EXTERNAL_NAMED_OK','COMPACT_LINUX_RESULT status=11 exited=0 exit=0 steps=100 syscalls=10','FLEX_EXTERNAL_DEADLINE_DENIED','EXTERNAL_HTTP_FAILED line=39 errno=101','FLEX_EXTERNAL_UNGRANTED_DENIED','FLEX_EXTERNAL_END','FLEX_EXTERNAL_DONE']
        serial=('\n'.join(lines)+'\n').encode();digests={'external-http':digest,'external-hosts':digest}
        self.assertTrue(gate.inspect(serial,commit,digests,len(gate.CASES)+2,1)['passed'])
        for token in ('FLEX_EXTERNAL_DONE','FLEX_EXTERNAL_UNGRANTED_DENIED','FLEX_EXTERNAL_DEADLINE_DENIED','E_peek_'+commit,digest):self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests,len(gate.CASES)+2,1)['passed'])
        self.assertFalse(gate.inspect(serial,commit,digests,0,1)['passed']);self.assertFalse(gate.inspect(serial.replace(b'exit=0',b'exit=1',1),commit,digests,len(gate.CASES)+2,1)['passed'])
        self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        delay=self.server.delay
        if delay:time.sleep(delay)
        data=b'FLEX_EXTERNAL_SOURCE_challenge\n';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError):pass
    def log_message(self,*args):pass

@unittest.skipUnless(os.environ.get('COMPACT_MUSL_DIR'),'set COMPACT_MUSL_DIR to pinned musl fixtures')
class ExternalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
        cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'http';cls.raw=cls.directory/'raw'
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        cls.cache=Path(os.environ['COMPACT_MUSL_DIR']).resolve();cls.libc=cls.cache/'musl-libc.so'
        subprocess.run([str(cls.cache/'install/bin/musl-gcc'),'-O1','-fPIE','-pie','-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1',str(ROOT/'tests/fixtures/compact_external_http.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_external_raw.c'),'-o',str(cls.raw)],check=True,capture_output=True)
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.server.requests=[];cls.server.delay=0
        cls.thread=threading.Thread(target=lambda:cls.server.serve_forever(poll_interval=.01),daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.tmp.cleanup()
    def vm(self,mode,*,runner=None,grant=True,extra=(),env=None):
        command=[str(runner or self.runner),'-b','4194304','-x',f'/lib/ld-musl-x86_64.so.1={self.libc}']
        if grant:command+=['-n',f'10.20.30.40:8080=127.0.0.1:{self.server.server_port}']
        return subprocess.run([*command,*extra,str(self.fixture),mode,'FLEX_EXTERNAL_SOURCE_challenge','challenge'],env=env,capture_output=True,timeout=12)
    def test_real_tcp_http_poll_peek_nonblocking_and_shared_fork_match_linux(self):
        for mode in ('http','poll','peek','msg-peek','nonblock','fork'):
            with self.subTest(mode=mode):
                vm=self.vm(mode);self.assertEqual(vm.returncode,0,vm.stderr)
                env=dict(os.environ,FLEX_EXTERNAL_NATIVE_ADDR=f'127.0.0.1:{self.server.server_port}')
                native=subprocess.Popen([str(self.libc),str(self.fixture),mode,'FLEX_EXTERNAL_SOURCE_challenge','challenge'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    out,err=native.communicate(timeout=10);self.assertEqual(native.returncode,0,err);self.assertEqual(vm.stdout,out)
                finally:
                    try:os.killpg(native.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                self.assertEqual(vm.stdout,f'FLEX_EXTERNAL_OK {mode}\nchallenge\n'.encode())
    def test_grant_denial_and_exclusive_connection_reuse(self):
        before=len(self.server.requests);vm=self.vm('denied');self.assertEqual(vm.returncode,0,vm.stderr)
        vm=self.vm('http',grant=False);self.assertEqual(vm.returncode,2);self.assertIn(b'errno=101',vm.stderr);self.assertEqual(len(self.server.requests),before)
        vm=self.vm('duplicate');self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(len(self.server.requests),before+1)
    def test_unresponsive_peer_is_bounded_by_wall_budget(self):
        self.server.delay=1;before=len(self.server.requests);start=time.monotonic()
        try:vm=self.vm('timeout',extra=('-t','300'))
        finally:self.server.delay=0
        self.assertEqual(vm.returncode,2,vm.stderr);self.assertIn(b'status=11 ',vm.stderr);self.assertEqual(len(self.server.requests),before+1);self.assertLess(time.monotonic()-start,2)
    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox')
    def test_unmodified_wget_download_and_persistent_reload(self):
        busybox=Path(os.environ['COMPACT_SHELL_DIR']).resolve()/'busybox';url='http://10.20.30.40:8080/external-probe.txt';expected=b'FLEX_EXTERNAL_SOURCE_challenge\n'
        base=[str(self.runner),'-b','4194304','-n',f'10.20.30.40:8080=127.0.0.1:{self.server.server_port}']
        vm=subprocess.run([*base,str(busybox),'wget','-Y','off','-q','-O','-',url],capture_output=True,timeout=10)
        native=subprocess.run([str(busybox),'wget','-Y','off','-q','-O','-',f'http://127.0.0.1:{self.server.server_port}/external-probe.txt'],capture_output=True,timeout=10)
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout);self.assertEqual(vm.stdout,expected)
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'download.fs'
            download=subprocess.run([*base,'-W',str(state),str(busybox),'wget','-Y','off','-q','-O','/tmp/download',url],capture_output=True,timeout=10)
            self.assertEqual(download.returncode,0,download.stderr);self.assertEqual(download.stdout,b'')
            reload=subprocess.run([str(self.runner),'-R',str(state),str(busybox),'cat','/tmp/download'],capture_output=True,timeout=10)
            self.assertEqual(reload.returncode,0,reload.stderr);self.assertEqual(reload.stdout,expected)
            hosts=Path(directory)/'hosts';hosts.write_text('10.20.30.40 resource.flex.test\n')
            named=[*base,'-x',f'/etc/hosts={hosts}',str(busybox),'wget','-Y','off','-q','-O','-','http://resource.flex.test:8080/external-probe.txt']
            mapped=subprocess.run(named,capture_output=True,timeout=10);self.assertEqual(mapped.returncode,0,mapped.stderr);self.assertEqual(mapped.stdout,expected)
            before=len(self.server.requests);hosts.write_text('10.20.30.41 resource.flex.test\n')
            denied=subprocess.run(named,capture_output=True,timeout=10);self.assertEqual(denied.returncode,2);self.assertEqual(len(self.server.requests),before)
    def test_provider_contracts_budgets_and_exactly_once_ownership_under_sanitizers(self):
        runner=self.directory/'resources';sources=[p for p in self.sources if not p.endswith('jobs_probe.c')]
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*sources,str(ROOT/'tests/phase9_external_resources_test.c'),'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        result=subprocess.run([str(runner),str(self.raw)],env=env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'FLEX_EXTERNAL_RESOURCES_OK\n')
    def test_real_io_under_address_undefined_and_leak_checks(self):
        runner=self.directory/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in ('http','poll','peek','msg-peek','nonblock','fork','duplicate','denied'):
            with self.subTest(mode=mode):
                vm=self.vm(mode,runner=runner,env=env);self.assertEqual(vm.returncode,0,vm.stderr);self.assertNotIn(b'AddressSanitizer',vm.stderr)
    def test_closed_standard_fds_do_not_become_network_handles(self):
        base=[str(self.runner),'-b','4194304','-x',f'/lib/ld-musl-x86_64.so.1={self.libc}','-n',f'10.20.30.40:8080=127.0.0.1:{self.server.server_port}',str(self.fixture),'closed-stdio','FLEX_EXTERNAL_SOURCE_challenge','challenge']
        before=len(self.server.requests)
        for script in ('exec 1>&-; exec "$@"','exec 0<&-; exec 1>&-; exec "$@"'):
            result=subprocess.run(['/bin/sh','-c',script,'closed-stdio',*base],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'')
            self.assertIn(b'FLEX_EXTERNAL_OK closed-stdio\nchallenge\n',result.stderr)
        self.assertEqual(len(self.server.requests),before+2)
    def test_cli_rejects_bad_and_duplicate_grants_before_opening_connections(self):
        for text in ('999.1.2.3:80=127.0.0.1:1','10.1.2.3:0=127.0.0.1:1','10.1.2.3:80=','1.2.3:80=127.0.0.1:1'):
            vm=self.vm('http',grant=False,extra=('-n',text));self.assertNotEqual(vm.returncode,0);self.assertNotIn(b'FLEX_EXTERNAL_OK',vm.stdout)
        spec=f'10.20.30.40:8080=127.0.0.1:{self.server.server_port}'
        vm=self.vm('http',grant=False,extra=('-n',spec,'-n',spec));self.assertEqual(vm.returncode,2);self.assertIn(b'status=1 ',vm.stderr)
if __name__=='__main__':unittest.main()
