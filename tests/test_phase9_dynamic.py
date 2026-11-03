# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import struct
import sys
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))

@unittest.skipUnless(os.environ.get('COMPACT_MUSL_DIR'),'set COMPACT_MUSL_DIR to pinned-source musl fixtures')
class DynamicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
        c=ROOT/'ryzova/compat/linux'
        cls.sources=[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.runner=cls.directory/'runner';cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        cls.fixtures=Path(os.environ['COMPACT_MUSL_DIR']).resolve();cls.libc=cls.fixtures/'musl-libc.so';cls.library=cls.fixtures/'libflex.so'
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def vm(self,binary,*args,runner=None,grants=None,env=None):
        command=[str(runner or self.runner)]
        for path in grants if grants is not None else [f'/lib/ld-musl-x86_64.so.1={self.libc}',f'/lib/libflex.so={self.library}']:command+=['-x',path]
        return subprocess.run([*command,str(binary),*args],capture_output=True,timeout=20,env=env)
    def test_unmodified_linker_tls_heap_stdio_shared_library_and_dlopen(self):
        for name,expected in [('hello',b'FLEX_DYNAMIC_OK 7 challenge\n'),('dlopen',b'FLEX_DLOPEN_OK 29\n'),('needed',b'FLEX_NEEDED_OK 29\n')]:
            with self.subTest(name=name):
                elf=self.fixtures/('dynamic-'+name)
                vm=self.vm(elf,*(['challenge'] if name=='hello' else []))
                self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,expected)
                native_args=['challenge',str(self.directory/'native-file')] if name=='hello' else ([str(self.library)] if name=='dlopen' else [])
                native=subprocess.run([str(self.libc),'--library-path',str(self.fixtures),str(elf),*native_args],capture_output=True,timeout=10)
                self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(native.stdout,vm.stdout)
    def test_mapping_permissions_entropy_and_memory_barrier_contract(self):
        vm=self.vm(self.fixtures/'dynamic-memory','challenge',grants=[f'/library={self.library}'])
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'FLEX_MEMORY_OK\nchallenge\n')
    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox')
    def test_failed_dynamic_exec_keeps_files_and_shell_alive(self):
        busybox=Path(os.environ['COMPACT_SHELL_DIR']).resolve()/'busybox'
        vm=self.vm(busybox,'ash','-c','echo keep > /tmp/f; /bad; /busybox cat /tmp/f; echo alive',grants=[f'/bad={self.fixtures/"dynamic-hello"}','/busybox'])
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'keep\nalive\n')

    def test_real_guest_compiler_produces_an_executable_elf(self):
        compiler=self.fixtures/'tcc-fixture'
        if not compiler.exists():self.skipTest('build TinyCC fixture with scripts/phase9_compiler.py')
        import phase9_compiler
        source=self.directory/'input.c';source.write_bytes(phase9_compiler.source('a'*40))
        cmd=[str(self.runner),'-b','4194304','-x',f'/lib/ld-musl-x86_64.so.1={self.libc}','-i',str(source),str(compiler),'-nostdinc','-nostdlib','-static','-o','/output','-x','c','/input']
        result=subprocess.run(cmd,capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(result.stdout.startswith(b'\x7fELF'))
        generated=self.directory/'generated';generated.write_bytes(result.stdout)
        vm=self.vm(generated,grants=[])
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'FLEX_COMPILED_IN_GUEST\nC_'+b'a'*40+b'\n')
        # This executes only the known freestanding fixture, on Linux, as a
        # differential reference after generating it entirely inside the VM.
        generated.chmod(0o700)
        native=subprocess.run([str(generated)],capture_output=True,timeout=5)
        self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(native.stdout,vm.stdout)

    def test_loader_rejects_missing_interpreter_and_unsafe_segments(self):
        image=(self.fixtures/'dynamic-hello').read_bytes()
        self.assertIn(b'status=1 ',self.vm(self.fixtures/'dynamic-hello',grants=[]).stderr)
        phoff=struct.unpack_from('<Q',image,32)[0];num=struct.unpack_from('<H',image,56)[0]
        variants=[]
        for i in range(num):
            off=phoff+i*56
            if struct.unpack_from('<I',image,off)[0]==1:
                data=bytearray(image);struct.pack_into('<I',data,off+4,7);variants.append(data)
        data=bytearray(image);struct.pack_into('<Q',data,32,2**64-1);variants.append(data)
        data=bytearray(image);struct.pack_into('<Q',data,24,2**64-1);variants.append(data)
        for data in variants:
            file=self.directory/'bad-elf';file.write_bytes(data)
            vm=self.vm(file);self.assertEqual(vm.returncode,2);self.assertIn(b'status=1 ',vm.stderr)
    def test_dynamic_execution_under_sanitizers(self):
        runner=self.directory/'asan'
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for name in ('hello','dlopen','needed'):
            vm=self.vm(self.fixtures/('dynamic-'+name),*(['challenge'] if name=='hello' else []),runner=runner,env=env)
            self.assertEqual(vm.returncode,0,vm.stderr);self.assertNotIn(b'AddressSanitizer',vm.stderr)
    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox')
    def test_fork_exec_into_dynamic_image_preserves_guest_namespace(self):
        busybox=Path(os.environ['COMPACT_SHELL_DIR']).resolve()/'busybox';binary=self.fixtures/'dynamic-hello'
        grants=[f'/lib/ld-musl-x86_64.so.1={self.libc}',f'/app={binary}']
        vm=self.vm(busybox,'ash','-c','/app challenge; echo done',grants=grants)
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'FLEX_DYNAMIC_OK 7 challenge\ndone\n')

if __name__=='__main__':unittest.main()
