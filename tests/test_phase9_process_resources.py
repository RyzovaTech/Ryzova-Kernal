# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-03 shared memory, futex, process sessions and enforced limits."""
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
SHARED=('basic','fork','fixed','release','anon-futex','file-futex','private-futex','bitset','requeue','timeout','unmap-wait')
PROCESS=('sessions','groups','nofile','hard-limit','address-limit','prlimit','exec')
BOUNDED=('quota','nproc','arena-budget','key-pin-quota')
class RuntimeTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.d=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
  cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
  cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
  cls.runner=cls.d/'runner';cls.fixture=cls.d/'fixture'
  subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
  subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_runtime.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def guest(self,mode,runner=None,env=None):
  extra=['-B','16777216'] if mode=='arena-budget' else []
  r=subprocess.run([str(runner or self.runner),*extra,'-x',str(self.fixture),str(self.fixture),'/tmp/runtime',mode,'challenge'],capture_output=True,timeout=20,env=env)
  self.assertEqual(r.returncode,0,(mode,r.stderr));self.assertEqual(r.stdout,f'FLEX_PROC_RESOURCE_OK {mode}\nchallenge\n'.encode());return r
 def native(self,mode,d):
  p=subprocess.Popen([str(self.fixture),d+'/file',mode,'challenge'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  try:out,err=p.communicate(timeout=12)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);p.communicate();raise
  finally:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  return subprocess.CompletedProcess(p.args,p.returncode,out,err)
 def test_shared_anonymous_and_futex_match_linux(self):
  for mode in SHARED:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
    vm=self.guest(mode);native=self.native(mode,d)
    self.assertEqual(native.returncode,0,(mode,native.stderr));self.assertEqual(vm.stdout,native.stdout)
 def test_process_groups_sessions_and_limits_match_linux(self):
  for mode in PROCESS:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
    vm=self.guest(mode);native=self.native(mode,d)
    self.assertEqual(native.returncode,0,(mode,native.stderr));self.assertEqual(vm.stdout,native.stdout)
 def test_bounded_pool_and_task_limit(self):
  for mode in BOUNDED:
   r=self.guest(mode)
   if mode=='arena-budget':self.assertIn(b'arena_peak=16777216 shared_peak=1',r.stderr)
 def test_shared_key_pins_reclamation_and_aba_identity(self):
  checker=self.d/'lifetime'
  subprocess.run([*self.flags,*self.sources[:-1],str(ROOT/'tests/phase9_shared_lifetime_test.c'),'-o',str(checker)],check=True,capture_output=True)
  r=subprocess.run([str(checker)],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
 def test_native_gate_rejects_missing_challenges_results_or_measurements(self):
  import phase9_process_resources as gate
  commit,digest='a'*40,'b'*64
  lines=[digest+'  /tmp/rt-elf']+[f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]+['FLEX_PROC_RESOURCE_BEGIN']
  for mode in gate.CASES:
   lines += ['FLEX_PROC_RESOURCE_OK '+mode,'C_'+mode+'_'+commit,'COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10','COMPACT_RESOURCE_STATS arena_peak=16777216 shared_peak=1','FLEX_PROC_RESOURCE_'+mode+'_RUN_OK']
  lines+=['FLEX_PROC_RESOURCE_END','FLEX_PROC_RESOURCE_DONE'];serial=('\n'.join(lines)+'\n').encode();digests={'runtime.elf':digest}
  self.assertTrue(gate.inspect(serial,commit,digests)['passed'])
  for token in ('FLEX_PROC_RESOURCE_DONE','C_requeue_'+commit,digest,'FLEX_PROC_RESOURCE_unmap-wait_RUN_OK'):
   self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
  self.assertFalse(gate.inspect(serial.replace(b'arena_peak=16777216',b'arena_peak=999999999',1),commit,digests)['passed'])
  self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed'])
  self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))
 def test_allocation_failure_balance(self):
  checker=self.d/'allocation-check'
  subprocess.run([*self.flags,*self.sources[:-1],str(ROOT/'tests/phase9_shared_allocations_test.c'),'-Wl,--wrap=malloc,--wrap=free','-o',str(checker)],check=True,capture_output=True)
  r=subprocess.run([str(checker),str(self.fixture)],capture_output=True,timeout=35);self.assertEqual(r.returncode,0,r.stderr)
 def test_address_undefined_and_leak_sanitizers(self):
  runner=self.d/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
  env=dict(os.environ)
  if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
  for mode in (*SHARED,*PROCESS,*BOUNDED):self.guest(mode,runner,env)
if __name__=='__main__':unittest.main()
