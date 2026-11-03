# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-03A private file mappings: Linux reference, backing-store and lifetime tests."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from phase9_process import FLAGS
CASES = ('basic','readonly','fork','clean-fork','page-granularity','offset','mixed','io','unlink','release','bus','tail','fixed','futex','exec')


class PrivateMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        core = ROOT / 'ryzova/compat/linux'
        cls.sources = [str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.flags = ['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        cls.runner, cls.fixture = cls.directory/'runner', cls.directory/'fixture'
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_private_maps.c'),'-o',str(cls.fixture)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def guest(self, mode, *flags, runner=None, env=None):
        return subprocess.run([str(runner or self.runner),*map(str,flags),'-x',str(self.fixture),str(self.fixture),'/tmp/private',mode,'challenge'],capture_output=True,timeout=25,env=env)

    def check(self, mode, *flags, **kwargs):
        r = self.guest(mode,*flags,**kwargs)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout,f'FLEX_PRIVATE_OK {mode}\nchallenge\n'.encode())
        return r

    def test_private_file_cow_and_fork_semantics_match_linux(self):
        for mode in CASES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                vm = self.check(mode)
                native = subprocess.run([str(self.fixture),directory+'/private',mode,'challenge'],capture_output=True,timeout=25)
                self.assertEqual(native.returncode,0,native.stderr)
                self.assertEqual(vm.stdout,native.stdout)

    def test_dirty_private_bytes_never_enter_filesystem_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state'
            self.check('create','-W',path)
            self.check('reload','-R',path)

    def test_bounded_file_binding_quota_is_reclaimed_after_unmap(self):
        self.check('quota')

    def test_allocation_failures_release_private_inode_holds_and_fork_arenas(self):
        checker=self.directory/'allocation-check'
        subprocess.run([*self.flags,*self.sources[:-1],str(ROOT/'tests/phase9_shared_allocations_test.c'),'-Wl,--wrap=malloc,--wrap=free','-o',str(checker)],check=True,capture_output=True)
        r=subprocess.run([str(checker),str(self.fixture)],capture_output=True,timeout=35)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout,b'FLEX_MAP_ALLOCATION_BALANCE_PASS\n')

    def test_native_gate_requires_each_challenge_digest_and_private_reload(self):
        import phase9_private_maps as gate
        commit,digest='a'*40,'b'*64
        clean='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines=[digest+'  /tmp/pr-elf']+[f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]
        lines+=['FLEX_PRIVATE_BEGIN']
        for mode in gate.CASES:
            lines+=['FLEX_PRIVATE_OK '+mode,'C_'+mode+'_'+commit,clean,'FLEX_PRIVATE_'+mode+'_RUN_OK']
        for mode,marker in (('create','SAVE'),('reload','RELOAD')):
            lines+=['FLEX_PRIVATE_OK '+mode,'C_saved_'+commit,clean,'FLEX_PRIVATE_'+marker+'_OK']
        lines+=['FLEX_PRIVATE_END','FLEX_PRIVATE_DONE']
        serial=('\n'.join(lines)+'\n').encode();digests={'private-maps.elf':digest}
        evidence=gate.inspect(serial,commit,digests)
        self.assertTrue(evidence['passed']);self.assertFalse(evidence['phase_complete'])
        for token in ('FLEX_PRIVATE_DONE','FLEX_PRIVATE_RELOAD_OK','C_fork_'+commit,'C_tail_'+commit,digest):
            self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
        self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed'])
        self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))

    def test_address_undefined_and_leak_sanitizers(self):
        runner=self.directory/'asan'
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in (*CASES,'quota'):
            self.check(mode,runner=runner,env=env)


if __name__=='__main__':
    unittest.main()
