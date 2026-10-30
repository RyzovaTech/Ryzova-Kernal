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
import phase9_shared_maps as gate

CASES=('basic','fork','unlink','tail','bus','bus-handler','bus-context','bus-flags','write-only','offset','fixed','io','exec','exec-cycle','syscall-fault','bus-blocked','errors','release')
class SharedMapTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
  cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
  cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all'];cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
  subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
  subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_shared_maps.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
  cls.libc=None
  if os.environ.get('COMPACT_MUSL_DIR'):
   musl=Path(os.environ['COMPACT_MUSL_DIR']).resolve();cls.libc=musl/'musl-libc.so';cls.application=cls.directory/'application'
   subprocess.run([str(musl/'install/bin/musl-gcc'),'-O1','-pthread','-fPIE','-pie','-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1',str(ROOT/'tests/fixtures/compact_shared_musl.c'),'-o',str(cls.application)],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def run_guest(self,mode,*flags,runner=None,env=None):
  return subprocess.run([str(runner or self.runner),*map(str,flags),'-x',str(self.fixture),str(self.fixture),'/tmp/links',mode,'challenge'],capture_output=True,timeout=20,env=env)
 def check_guest(self,mode,*flags,**kwargs):
  result=self.run_guest(mode,*flags,**kwargs);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,f'FLEX_MAP_OK {mode}\nchallenge\n'.encode());return result
 def test_linux_differential_inode_data_metadata_and_lifetimes(self):
  for mode in CASES:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
    vm=self.check_guest(mode);native=subprocess.run([str(self.fixture),directory+'/links',mode,'challenge'],capture_output=True,timeout=20)
    self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout)
 def test_page_binding_quota_and_reclamation(self):
  for mode in ('quota','permissions','output-alias','futex-policy'):self.check_guest(mode)
 def test_mapping_writes_are_persisted_without_an_open_descriptor(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';self.check_guest('create','-W',path);self.check_guest('reload','-R',path)
 def test_native_gate_requires_sigbus_cases_every_challenge_and_reload(self):
  commit='a'*40;digest='b'*64;digests={name:digest for name in ('shared-maps.elf','shared-map-app')}
  lines=['memory=shared-guest-files shared-file-pages=64 sync=instruction-and-syscall-boundaries bus=guest-SIGBUS',digest+'  /tmp/mm-elf',digest+'  /tmp/mm-app']
  lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]
  result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10';lines += ['FLEX_MAP_BEGIN']
  for mode in gate.CASES:lines += ['FLEX_MAP_OK '+mode,'M_'+mode+'_'+commit,result,'FLEX_MAP_'+mode+'_RUN_OK']
  for mode,marker in (('create','SAVE'),('reload','RELOAD')):lines += ['FLEX_MAP_OK '+mode,'M_saved_'+commit,result,'FLEX_MAP_'+marker+'_OK']
  lines += ['FLEX_MAP_MUSL_OK','M_musl_'+commit,result,'FLEX_MAP_MUSL_RUN_OK','FLEX_MAPPED_FILE',result,'FLEX_MAP_BUSYBOX_OK','COMPACT_LINUX_RESULT status=4 exited=0 exit=0 steps=10000 syscalls=6','FLEX_MAP_LIMIT_OK','FLEX_MAP_OK fault-reload','M_fault_'+commit,result,'FLEX_MAP_FAULT_RELOAD_OK','FLEX_MAP_END','FLEX_MAP_DONE']
  serial=('\n'.join(lines)+'\n').encode();self.assertTrue(gate.inspect(serial,commit,digests)['passed'])
  for token in ('FLEX_MAP_DONE','FLEX_MAP_RELOAD_OK','M_bus-handler_'+commit,'FLEX_MAP_MUSL_OK',digest,'FLEX_MAPPED_FILE','status=4','FLEX_MAP_FAULT_RELOAD_OK'):
   self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
  self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed']);self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))
 def test_step_limit_exports_completed_mapping_changes(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';result=self.run_guest('fault','-b','10000','-W',path)
   self.assertEqual(result.returncode,2,result.stderr);self.assertIn(b'status=4 ',result.stderr);self.assertEqual(result.stdout,b'');self.check_guest('fault-reload','-R',path)
 def test_allocation_failures_release_mapping_baselines_and_fork_images(self):
  checker=self.directory/'allocation-check';sources=[s for s in self.sources if not s.endswith('jobs_probe.c')]
  subprocess.run([*self.flags,*sources,str(ROOT/'tests/phase9_shared_allocations_test.c'),'-Wl,--wrap=malloc,--wrap=free','-o',str(checker)],check=True,capture_output=True)
  result=subprocess.run([str(checker),str(self.fixture)],capture_output=True,timeout=30);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'FLEX_MAP_ALLOCATION_BALANCE_PASS\n')
 def run_application(self,runner=None,env=None,*flags):
  return subprocess.run([str(runner or self.runner),'-b','4194304',*map(str,flags),'-x','/lib/ld-musl-x86_64.so.1='+str(self.libc),str(self.application),'/tmp/map-app','challenge'],capture_output=True,timeout=20,env=env)
 @unittest.skipUnless(os.environ.get('COMPACT_MUSL_DIR'),'set COMPACT_MUSL_DIR to pinned musl fixture')
 def test_musl_pthread_atomics_and_fork_mapping_match_linux(self):
  vm=self.run_application();self.assertEqual(vm.returncode,0,vm.stderr)
  with tempfile.TemporaryDirectory() as directory:native=subprocess.run([str(self.libc),str(self.application),directory+'/case','challenge'],capture_output=True,timeout=20)
  self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout);self.assertEqual(vm.stdout,b'FLEX_MAP_MUSL_OK\nchallenge\n')
 @unittest.skipUnless(os.environ.get('COMPACT_MUSL_DIR') and os.environ.get('COMPACT_SHELL_DIR'),'set pinned musl and BusyBox fixtures')
 def test_mapped_application_data_is_read_by_unmodified_busybox_after_reload(self):
  busybox=(ROOT/os.environ['COMPACT_SHELL_DIR']/'busybox').resolve();self.assertEqual(hashlib.sha256(busybox.read_bytes()).hexdigest(),DIGEST)
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';result=self.run_application(None,None,'-W',path);self.assertEqual(result.returncode,0,result.stderr)
   result=subprocess.run([str(self.runner),'-R',str(path),str(busybox),'head','-c','17','/tmp/map-app/file'],capture_output=True,timeout=20)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'FLEX_MAPPED_FILE\n')
 def test_address_undefined_and_leak_checks(self):
  runner=self.directory/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True);env=dict(os.environ)
  if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
  for mode in (*CASES,'quota','permissions','output-alias','futex-policy'):self.check_guest(mode,runner=runner,env=env)
  if self.libc:
   result=self.run_application(runner,env);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'FLEX_MAP_MUSL_OK\nchallenge\n')
if __name__=='__main__':unittest.main()
