# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_jobs import build,commands,inspect,SCRIPT,DATA,CASES
from phase9_shell import DIGEST


class JobsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
        c=ROOT/'ryzova/compat/linux'
        cls.sources=[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        cls.digest=build(cls.fixture)
        cls.busybox=(Path(os.environ.get('COMPACT_SHELL_DIR','/nonexistent'))/'busybox').resolve()
        cls.bin=cls.directory/'bin';cls.bin.mkdir()
        if cls.busybox.exists():
            for name in ('cat','grep','wc','busybox'):(cls.bin/name).symlink_to(cls.busybox)

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def run_vm(self,binary,*args,grants=None,input=None,runner=None,env=None):
        cmd=[str(runner or self.runner)]
        for grant in grants if grants is not None else [str(binary)]:cmd+=['-x',str(grant)]
        if input is not None:
            path=self.directory/'input';path.write_bytes(input);cmd+=['-i',str(path)]
        return subprocess.run([*cmd,str(binary),*args],capture_output=True,timeout=20,env=env)

    def fixture_vm(self,mode,**kw):return self.run_vm(self.fixture,mode,'source-challenge',**kw)

    def test_fork_vfork_backpressure_exec_and_wait_match_linux(self):
        for mode in ('private','vfork','pipe','exec','vfork-exec','offset','wait-errors'):
            with self.subTest(mode=mode):
                # /input exists only inside the explicit virtual grant, so offset is
                # checked against its deterministic reference marker separately.
                vm=self.fixture_vm(mode,input=DATA if mode=='offset' else None)
                self.assertEqual(vm.returncode,0,vm.stderr)
                self.assertEqual(vm.stdout,b'FLEX_JOBS_FIXTURE_OK\nsource-challenge\n')
                if mode not in ('offset','wait-errors'):
                    native=subprocess.run([str(self.fixture),mode,'source-challenge'],capture_output=True,timeout=10)
                    self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout)
                if mode=='pipe':
                    self.assertRegex(vm.stderr,rb'blocked=[1-9][0-9]* ')
                    self.assertIn(b'pipebytes=81920',vm.stderr)
                if mode in ('exec','vfork-exec'):self.assertIn(b'execs=1 ',vm.stderr)

    def test_group_quotas_no_partial_truncate_and_nonblocking_endpoints(self):
        for mode in ('capacity','descriptions','quota','exec-quota','nonblock','io-quota','console'):
            with self.subTest(mode=mode):
                vm=self.fixture_vm(mode,input=DATA if mode=='descriptions' else None)
                self.assertEqual(vm.returncode,0,vm.stderr)
                expected=b'FLEX_JOBS_FIXTURE_OK\nsource-challenge\n'+(b'keep\n' if mode=='descriptions' else b'')
                self.assertEqual(vm.stdout,b'z'*65536 if mode=='console' else expected)
                if mode in ('capacity','descriptions'):self.assertIn(b'peak=8 ',vm.stderr)
                if mode=='quota':self.assertIn(b'forks=32 ',vm.stderr)
                if mode=='exec-quota':self.assertIn(b'execs=64 ',vm.stderr)
                if mode=='io-quota':self.assertIn(b'pipebytes=4194304 ',vm.stderr)

    def test_exec_denials_are_atomic_and_aliases_are_explicit(self):
        vm=self.fixture_vm('denied')
        self.assertEqual(vm.returncode,0,vm.stderr)
        vm=self.fixture_vm('exec',grants=[])
        self.assertEqual(vm.returncode,2);self.assertNotIn(b'FLEX_JOBS_FIXTURE_OK',vm.stdout)
        for aliases in (['relative'],['/input'],['/bin/../probe'],['/bin//probe'],['/bin/probe/'],['/x','/x'],['/'+('x'*255)]):
            vm=self.fixture_vm('private',grants=aliases,input=DATA)
            self.assertEqual(vm.returncode,2);self.assertIn(b'status=1 ',vm.stderr);self.assertEqual(vm.stdout,b'')

    def test_deadlock_and_instruction_budget_do_not_hang(self):
        vm=self.fixture_vm('deadlock')
        self.assertEqual(vm.returncode,2);self.assertIn(b'status=8 ',vm.stderr)
        self.assertEqual(vm.stdout,b'')

    def test_scheduler_under_address_and_undefined_sanitizers(self):
        runner=self.directory/'asan-runner'
        subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':
            env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        for mode in ('private','vfork','exec','vfork-exec','pipe','descriptions','capacity','exec-quota','deadlock','fault-child'):
            with self.subTest(mode=mode):
                vm=self.fixture_vm(mode,runner=runner,input=DATA if mode=='descriptions' else None,env=env)
                self.assertEqual(vm.returncode,2 if mode in ('deadlock','fault-child') else 0,vm.stderr)
                self.assertNotIn(b'AddressSanitizer',vm.stderr);self.assertNotIn(b'runtime error:',vm.stderr)

    def test_allocation_balance_repeated_groups_and_malloc_failures(self):
        runner=self.directory/'allocation-check'
        sources=[s for s in self.sources if not s.endswith('jobs_probe.c')]
        subprocess.run([*self.flags,*sources,str(ROOT/'tests/phase9_jobs_allocations_test.c'),
                        '-Wl,--wrap=malloc,--wrap=free','-o',str(runner)],check=True,capture_output=True)
        result=subprocess.run([str(runner),str(self.fixture)],capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'FLEX_JOBS_ALLOCATION_BALANCE_PASS',result.stdout)

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
    def test_unmodified_busybox_pipelines_substitutions_and_subshells_match_linux(self):
        self.assertEqual(hashlib.sha256(self.busybox.read_bytes()).hexdigest(),DIGEST)
        aliases=['/bin/busybox','/bin/cat','/bin/grep','/bin/wc']
        scripts=['echo hi | cat','printf "abc\\nxyz\\n" | grep xyz | wc -l',
                 'x=$(echo nested | cat); printf "[%s]\\n" "$x"',
                 'x=parent; (x=child; echo "$x"); echo "$x"',
                 'false | true; echo "$?"; true | false; echo "$?"',
                 '(exit 7); echo "exit=$?"']
        for script in scripts:
            with self.subTest(script=script):
                native=subprocess.run([str(self.busybox),'ash','-c',script],env={'PATH':str(self.bin)},capture_output=True,timeout=5)
                # Exact executable names are mapped to the same unmodified BusyBox
                # ELF; native ash may optimize its own standalone applets.
                vm=self.run_vm(self.busybox,'ash','-c',script,grants=aliases)
                self.assertEqual(native.returncode,0,native.stderr)
                self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,native.stdout)
                self.assertRegex(vm.stderr,rb'forks=[1-9][0-9]* ')

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
    def test_mixed_images_root_exec_and_bad_image_keep_namespace(self):
        script=f'{self.fixture} private mixed | {self.busybox} cat'
        vm=self.run_vm(self.busybox,'ash','-c',script,grants=[f'{self.fixture}={self.fixture}',str(self.busybox)])
        native=subprocess.run([str(self.busybox),'ash','-c',script],capture_output=True,timeout=5)
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,native.stdout)
        self.assertIn(b'execs=2 ',vm.stderr)
        script='echo saved >/output; exec /bin/busybox echo replaced'
        vm=self.run_vm(self.busybox,'ash','-c',script,grants=['/bin/busybox'],input=DATA)
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'replaced\nsaved\n')
        self.assertIn(b'forks=0 execs=1 ',vm.stderr)
        bad=self.directory/'not-elf';bad.write_bytes(b'not an ELF')
        vm=self.run_vm(self.busybox,'ash','-c','/bin/bad; echo survived',grants=[f'/bin/bad={bad}'])
        self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'survived\n')
        vm=self.run_vm(self.busybox,'ash','-c','while :; do :; done',grants=[])
        self.assertEqual(vm.returncode,2);self.assertIn(b'status=4 ',vm.stderr)
        vm=self.run_vm(self.busybox,'ash','-c','echo child & wait',grants=[])
        self.assertEqual(vm.returncode,2);self.assertIn(b'status=5 ',vm.stderr)

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
    def test_native_script_reference_output_and_group_isolation(self):
        vm=self.run_vm(self.busybox,'ash','/input','PJ_'+('a'*40),grants=['/busybox',f'/probe={self.fixture}'],input=SCRIPT)
        self.assertEqual(vm.returncode,0,vm.stderr)
        self.assertEqual(vm.stdout,b'FLEX_JOBS_OUTPUT\n1\nvalue=nested\nFLEX_JOBS_FIXTURE_OK\nPJ_'+b'a'*40+b'\nFLEX_JOBS_SCRIPT_OK\n')
        for _ in range(2):
            vm=self.run_vm(self.busybox,'ash','-c','echo fresh | /busybox cat',grants=['/busybox'])
            self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,b'fresh\n')
            self.assertIn(b'peak=3 ',vm.stderr)

    def test_native_evidence_rejects_missing_cases_stats_hashes_or_challenge(self):
        commit='a'*40;digest='b'*64
        lines=['linux-amd64-static-jobs-v1',digest+' /tmp/j-elf',hashlib.sha256(SCRIPT).hexdigest()+' /tmp/j-script',hashlib.sha256(DATA).hexdigest()+' /tmp/j-data',
               'FLEX_JOBS_BEGIN','FLEX_JOBS_OUTPUT','1','value=nested','FLEX_JOBS_FIXTURE_OK','PJ_'+commit,
               'FLEX_JOBS_SCRIPT_OK','COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=123 syscalls=50','FLEX_JOBS_RUN_OK']
        for mode in CASES:
            forks=32 if mode=='quota' else (7 if mode in ('capacity','descriptions') else 1)
            execs=64 if mode=='exec-quota' else (1 if mode in ('exec','vfork-exec') else 0)
            peak=8 if mode in ('capacity','descriptions') else 2
            pipebytes=4194304 if mode=='io-quota' else (81920 if mode=='pipe' else 0)
            lines+=['FLEX_JOBS_FIXTURE_OK',f'J_{mode}_{commit}','COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=123 syscalls=12',
                    f'COMPACT_JOBS_STATS forks={forks} execs={execs} peak={peak} blocked=1 pipebytes={pipebytes}',f'FLEX_JOB_{mode}_OK']
        lines+=['FLEX_JOBS_END','FLEX_JOBS_DONE']+[f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(94,94+len(commands(commit))-1)]
        raw=('\n'.join(lines)+'\n').encode();self.assertTrue(inspect(raw,commit,digest)['passed'])
        for value in (f'PJ_{commit}',f'J_vfork_{commit}','FLEX_JOB_exec_OK','pipebytes=81920',digest,'peak=8'):
            self.assertFalse(inspect(raw.replace(value.encode(),b'missing'),commit,digest)['passed'])
        self.assertTrue(all(len(c)<220 for c in commands(commit)))
