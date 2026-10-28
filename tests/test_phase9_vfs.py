# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
from phase9_shell import DIGEST
import phase9_vfs

class VfsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
        c=ROOT/'ryzova/compat/linux'
        cls.sources=[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_vfs.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
        cls.busybox=(Path(os.environ.get('COMPACT_SHELL_DIR','/nonexistent'))/'busybox').resolve()
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def test_native_gate_rejects_missing_or_mutated_evidence(self):
        commit='1'*40;digest='2'*64
        lines=['linux-amd64-local-tmp-v1',digest+'  /tmp/v-elf',hashlib.sha256(phase9_vfs.SCRIPT).hexdigest()+'  /tmp/v-script']
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(119,119+len(phase9_vfs.commands(commit))-1)]
        result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines += ['FLEX_VFS_BEGIN','FLEX_VFS_SHELL_OK',result,'FLEX_VFS_SHELL_RUN_OK']
        for mode in phase9_vfs.CASES:lines += ['FLEX_VFS_OK',f'V_{mode}_{commit}',result,f'FLEX_VFS_{mode}_OK']
        lines += ['FLEX_VFS_END','FLEX_VFS_DONE']
        serial=('\n'.join(lines)+'\n').encode()
        self.assertTrue(phase9_vfs.inspect(serial,commit,digest)['passed'])
        for marker in ('FLEX_VFS_DONE','FLEX_VFS_SHELL_RUN_OK',f'V_shared_{commit}',digest,'RYZOVA_RUNTIME_STAGE_119'):
            self.assertFalse(phase9_vfs.inspect(serial.replace(marker.encode(),b'MISSING'),commit,digest)['passed'])
        self.assertFalse(phase9_vfs.inspect(serial.replace(b'exit=0',b'exit=1',1),commit,digest)['passed'])
        self.assertTrue(all(len(c)<220 for c in phase9_vfs.commands(commit)))

    def test_compiled_file_directory_lifetimes_and_exec(self):
        for mode in ('basic','directory','unlink','errors','shared','quota','atomic','times','grants'):
            with self.subTest(mode=mode):
                grants=['-x','/tmp/bound'] if mode=='grants' else []
                vm=subprocess.run([str(self.runner),'-x',str(self.fixture),*grants,str(self.fixture),'/tmp/case',mode,'challenge'],capture_output=True,timeout=20)
                self.assertEqual(vm.returncode,0,vm.stderr)
                self.assertEqual(vm.stdout,b'FLEX_VFS_OK\nchallenge\n')
                # Resource bounds and fixed 24-byte getdents chunks are virtual
                # policies. Other cases also run directly on the Linux ABI.
                if mode in ('basic','unlink','shared','times'):
                    with tempfile.TemporaryDirectory() as d:
                        native=subprocess.run([str(self.fixture),d+'/case',mode,'challenge'],capture_output=True,timeout=10)
                    self.assertEqual(native.returncode,0,native.stderr)
                    self.assertEqual(vm.stdout,native.stdout)

    def test_vfs_with_address_and_undefined_sanitizers(self):
        runner=self.directory/'asan-vfs'
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in ('basic','directory','unlink','errors','shared','quota','atomic','times','grants'):
            with self.subTest(mode=mode):
                grants=['-x','/tmp/bound'] if mode=='grants' else []
                result=subprocess.run([str(runner),'-x',str(self.fixture),*grants,str(self.fixture),'/tmp/case',mode,'challenge'],env=env,capture_output=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertNotIn(b'AddressSanitizer',result.stderr)

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
    def test_host_files_are_isolated_and_invocations_reset(self):
        with tempfile.NamedTemporaryFile(prefix='flex-host-',dir='/tmp') as host:
            host.write(b'host-secret');host.flush()
            script=f'test ! -e {host.name}; echo virtual > {host.name}; /busybox cat {host.name}'
            for _ in range(2):
                result=subprocess.run([str(self.runner),'-x','/busybox',str(self.busybox),'ash','-c','set -e; '+script],capture_output=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,b'virtual\n')
                self.assertEqual(Path(host.name).read_bytes(),b'host-secret')

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
    def test_busybox_writable_shell_workflows_match_linux(self):
        self.assertEqual(hashlib.sha256(self.busybox.read_bytes()).hexdigest(),DIGEST)
        scripts=[
            'mkdir -p TMP/a/b; echo hello > TMP/a/b/file; cat TMP/a/b/file; wc -c < TMP/a/b/file',
            'mkdir TMP/a; echo one > TMP/a/first; cp TMP/a/first TMP/a/second; mv TMP/a/second TMP/a/third; cat TMP/a/third; rm TMP/a/first TMP/a/third; rmdir TMP/a; echo done',
            'echo one > TMP/f; echo two >> TMP/f; cat TMP/f; : > TMP/f; wc -c < TMP/f',
            'mkdir TMP/a; cd TMP/a; echo shared > f; (echo child >> f); cat f; cd ..; mv a b; cat b/f',
            'mkdir TMP/a; touch TMP/a/x TMP/a/y; ls TMP/a; rm -r TMP/a; test ! -e TMP/a; echo removed',
        ]
        names=('busybox','mkdir','cat','wc','cp','mv','rm','rmdir','ls','touch')
        with tempfile.TemporaryDirectory() as d:
            bindir=Path(d)/'bin';bindir.mkdir()
            for name in names:(bindir/name).symlink_to(self.busybox)
            for script in scripts:
                with self.subTest(script=script),tempfile.TemporaryDirectory() as nd:
                    native=subprocess.run([str(self.busybox),'ash','-c','set -e; '+script.replace('TMP',nd)],env={'PATH':str(bindir)},capture_output=True,timeout=10)
                    cmd=[str(self.runner)]
                    for name in names:cmd+=['-x','/bin/'+name]
                    vm=subprocess.run([*cmd,str(self.busybox),'ash','-c','set -e; '+script.replace('TMP','/tmp')],capture_output=True,timeout=20)
                    self.assertEqual(native.returncode,0,native.stderr)
                    self.assertEqual(vm.returncode,0,vm.stderr)
                    self.assertEqual(vm.stdout,native.stdout)

if __name__=='__main__':unittest.main()
