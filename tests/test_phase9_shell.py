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
from phase9_shell import SCRIPT, DATA, DIGEST, commands, inspect


class ShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
        c=ROOT/'ryzova/compat/linux'
        cls.runner=cls.directory/'runner'
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        subprocess.run([*cls.flags,*[str(c/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','process_probe')],'-o',str(cls.runner)],check=True,capture_output=True)
        cls.binary=Path(os.environ.get('COMPACT_SHELL_DIR','/nonexistent'))/'busybox'

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def vm(self,*args,input=None):
        cmd=[str(self.runner)]
        if input is not None:
            path=self.directory/'input';path.write_bytes(input);cmd+=['-i',str(path)]
        return subprocess.run([*cmd,str(self.binary),*args],capture_output=True,timeout=10)

    def test_stat_signals_descriptors_and_permissions(self):
        binary=self.directory/'resources'
        c=ROOT/'ryzova/compat/linux'
        subprocess.run([*self.flags,str(c/'namespace.c'),str(c/'syscall.c'),str(ROOT/'tests/phase9_shell_resources_test.c'),'-o',str(binary)],check=True,capture_output=True)
        r=subprocess.run([str(binary)],capture_output=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr);self.assertIn(b'FLEX_SHELL_RESOURCES_PASS',r.stdout)

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned multicall fixture')
    def test_unmodified_shell_and_multicall_output_match_linux(self):
        self.assertEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(),DIGEST)
        cases=[('true',),('echo','hello'),('printf','%d %x\\n','123','255'),
               ('ash','-c','x=0; for n in 1 2 3; do x=$((x+n)); done; f() { printf "sum=%s\\n" "$1"; }; f "$x"; cd /tmp; pwd'),
               ('ash','-c','case "$1" in a*) echo match;; *) echo no;; esac','--','abc'),
               ('ash','-c','if test 4 -gt 2; then echo yes; fi; false || echo fallback'),
               ('ash','-c','echo "[$FLEX_MODE]"; printf "%s\\n" "සිංහල"')]
        for args in cases:
            with self.subTest(args=args):
                native=subprocess.run([str(self.binary),*args],env={'FLEX_MODE':'test'},capture_output=True,timeout=5)
                vm=self.vm(*args)
                self.assertEqual(native.returncode,0,native.stderr)
                self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,native.stdout)
        for args in [('cat','input'),('wc','-c','input')]:
            (self.directory/'input').write_bytes(DATA)
            native=subprocess.run([str(self.binary),*args],cwd=self.directory,capture_output=True,timeout=5)
            vm=self.vm(*args,input=DATA)
            self.assertEqual(vm.returncode,0,vm.stderr);self.assertEqual(vm.stdout,native.stdout)

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned multicall fixture')
    def test_script_input_redirection_append_and_denied_paths(self):
        r=self.vm('ash','/input','SH_'+('a'*40),input=SCRIPT)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout,b'FLEX_SHELL_OK\nSH_'+b'a'*40+b'\nsum=6\n/tmp\n')
        for script, expected in [('read x </input; echo "$x"',DATA),
                                 ('echo first >/output; echo second >>/output',b'first\nsecond\n'),
                                 ('test -f /input && echo file-ok; test ! -e /etc/passwd && echo isolated',b'file-ok\nisolated\n')]:
            r=self.vm('ash','-c',script,input=DATA)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,expected)
        r=self.vm('ash','-c','echo denied >/etc/passwd',input=DATA)
        self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'')
        self.assertIn(b'exit=1',r.stderr)
        # A fresh process cannot observe an earlier output grant.
        r=self.vm('ash','-c','test ! -s /output && echo fresh',input=DATA)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,b'fresh\n')

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned multicall fixture')
    def test_unfinished_process_operations_and_infinite_loop_fail_bounded(self):
        for script in ('echo hi | cat','x=$(echo hi); echo "$x"','while :; do :; done'):
            r=self.vm('ash','-c',script)
            self.assertEqual(r.returncode,2)
            self.assertRegex(r.stderr,rb'status=(4|5) ')
            self.assertNotIn(b'runtime error:',r.stderr)

    def test_native_evidence_rejects_missing_proof(self):
        commit='a'*40
        lines=[DIGEST+' /tmp/busybox',hashlib.sha256(SCRIPT).hexdigest()+' /tmp/shell-script',hashlib.sha256(DATA).hexdigest()+' /tmp/shell-data',
               'FLEX_SHELL_BEGIN','FLEX_SHELL_OK','SH_'+commit,'sum=6','/tmp','FLEX_SHELL_INPUT','first','second','17 /input']
        for name in ('SCRIPT','CAT','WC','READ','REDIRECT'):
            lines+=['COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=123 syscalls=12','FLEX_SHELL_'+name+'_OK']
        lines+=['FLEX_SHELL_END','FLEX_SHELL_DONE']+[f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(80,93)]
        raw=('\n'.join(lines)+'\n').encode()
        self.assertTrue(inspect(raw,commit)['passed'])
        for text in ('SH_'+commit,'sum=6','/tmp\n','FLEX_SHELL_READ_OK',DIGEST,'status=0','RYZOVA_RUNTIME_STAGE_92'):
            self.assertFalse(inspect(raw.replace(text.encode(),b'missing'),commit)['passed'])
        self.assertTrue(all(len(c)<220 for c in commands(commit)))
