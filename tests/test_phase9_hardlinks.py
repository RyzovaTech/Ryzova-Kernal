# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import struct
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
from test_phase9_persistence import records,seal
from phase9_shell import DIGEST
import phase9_hardlinks as gate
CASES=('basic','offsets','unlink-open','rename','symlinks','at','errors','shared','times','churn')
class HardlinkTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
  cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
  cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all'];cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
  subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
  subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_hardlinks.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def run_guest(self,mode,*flags,runner=None,env=None):
  return subprocess.run([str(runner or self.runner),*map(str,flags),'-x',str(self.fixture),str(self.fixture),'/tmp/links',mode,'challenge'],capture_output=True,timeout=20,env=env)
 def check_guest(self,mode,*flags,**kwargs):
  result=self.run_guest(mode,*flags,**kwargs);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,f'FLEX_HARDLINK_OK {mode}\nchallenge\n'.encode());return result
 def test_linux_differential_inode_data_metadata_and_lifetimes(self):
  for mode in CASES:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
    vm=self.check_guest(mode);native=subprocess.run([str(self.fixture),directory+'/links',mode,'challenge'],capture_output=True,timeout=20)
    self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout)
 def test_namespace_entry_quota_and_recycling(self):self.check_guest('quota');self.check_guest('grants')
 def test_saved_aliases_keep_shared_data_after_original_name_is_unlinked(self):
  with tempfile.TemporaryDirectory() as directory:
   a=Path(directory)/'one';b=Path(directory)/'two';self.check_guest('create','-W',a);self.assertEqual(a.read_bytes()[:8],b'FLEXFS3\n');self.check_guest('reload','-R',a,'-W',b);self.check_guest('reload-mutated','-R',b)
 def test_single_surviving_alias_exports_a_legacy_readable_data_record(self):
  with tempfile.TemporaryDirectory() as directory:
   a=Path(directory)/'one';self.check_guest('single','-W',a);self.assertEqual(a.read_bytes()[:8],b'FLEXFS2\n');self.check_guest('reload-single','-R',a)
 def test_saved_relative_symlink_aliases_retain_directory_specific_targets(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';self.check_guest('symlinks','-W',path);self.check_guest('reload-symlinks','-R',path)
 def test_malformed_inode_aliases_are_rejected_before_execution(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';bad=Path(directory)/'bad';out=Path(directory)/'out';self.check_guest('create','-W',path);data=path.read_bytes();offsets=records(data)
   alias=next(at for at in offsets if struct.unpack_from('<I',data,at+12)[0]==3);index=struct.unpack_from('<I',data,alias)[0];length=struct.unpack_from('<I',data,alias+28)[0];payload=alias+80+length
   changes=[(payload,struct.pack('<I',value)) for value in (0,2,index,32)]+[(alias+16,struct.pack('<Q',2000)),(alias+8,struct.pack('<I',0o777)),(alias+40,struct.pack('<Q',12345)),(0,b'FLEXFS2\n')]
   mutations=[]
   for at,value in changes:
    changed=bytearray(data);changed[at:at+len(value)]=value;mutations.append(seal(changed))
   # Add a structurally valid alias that points at another alias, not its inode.
   new=bytearray(data[alias:payload+4]);struct.pack_into('<I',new,0,5);name=b'fourth';struct.pack_into('<I',new,28,len(name));new=new[:80]+name+struct.pack('<I',index)
   changed=bytearray(data[:-8])+new+bytearray(8);struct.pack_into('<Q',changed,8,len(changed));struct.pack_into('<I',changed,16,len(offsets)+1);mutations.append(seal(changed))
   for i,value in enumerate(mutations):
    with self.subTest(mutation=i):
     bad.write_bytes(value);result=self.run_guest('reload','-R',bad,'-W',out);self.assertEqual(result.returncode,2,result.stderr);self.assertIn(b'status=1 ',result.stderr);self.assertEqual(result.stdout,b'');self.assertFalse(out.exists())
 @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
 def test_unmodified_busybox_ln_cp_shared_writes_and_link_counts(self):
  busybox=(ROOT/os.environ['COMPACT_SHELL_DIR']/'busybox').resolve();self.assertEqual(hashlib.sha256(busybox.read_bytes()).hexdigest(),DIGEST)
  script=self.directory/'script';script.write_bytes(gate.SCRIPT)
  result=subprocess.run([str(self.runner),'-b','4194304','-x','/busybox','-i',str(script),str(busybox),'ash','/input'],capture_output=True,timeout=20)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'3\n2\nhard-content\nshared-update\nFLEX_HARDLINK_SHELL_OK\n')
 def test_native_gate_requires_independent_inode_reload_and_every_challenge(self):
  commit='a'*40;digest='b'*64;digests={'hardlinks.elf':digest,'hardlinks-script':hashlib.sha256(gate.SCRIPT).hexdigest()}
  lines=['hardlinks=guest-inode-aliases','shared-inodes-format=FLEXFS3 import-extra=FLEXFS3',digest+'  /tmp/hl-elf',digests['hardlinks-script']+'  /tmp/hl-script']
  lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]
  result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10';lines += ['FLEX_HARDLINK_BEGIN']
  for mode in gate.CASES:lines += ['FLEX_HARDLINK_OK '+mode,'H_'+mode+'_'+commit,result,'FLEX_HARDLINK_'+mode+'_RUN_OK']
  for mode,marker,token in (('create','SAVE','saved'),('reload','RELOAD','saved'),('reload-mutated','MUTATED','saved'),('single','SINGLE','single'),('reload-single','SINGLE_RELOAD','single'),('symlinks','SYM_SAVE','sym'),('reload-symlinks','SYM_RELOAD','sym')):lines += ['FLEX_HARDLINK_OK '+mode,'H_'+token+'_'+commit,result,'FLEX_HARDLINK_'+marker+'_OK']
  lines += ['3','2','hard-content','shared-update','FLEX_HARDLINK_SHELL_OK',result,'FLEX_HARDLINK_SHELL_RUN_OK','FLEX_HARDLINK_END','FLEX_HARDLINK_DONE']
  serial=('\n'.join(lines)+'\n').encode();self.assertTrue(gate.inspect(serial,commit,digests)['passed'])
  for token in ('FLEX_HARDLINK_DONE','FLEX_HARDLINK_MUTATED_OK','H_churn_'+commit,'FLEX_HARDLINK_SHELL_OK',digest,'shared-update'):
   self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
  self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed']);self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))
 def test_address_undefined_and_leak_checks(self):
  runner=self.directory/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True);env=dict(os.environ)
  if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
  for mode in (*CASES,'quota','grants'):self.check_guest(mode,runner=runner,env=env)
if __name__=='__main__':unittest.main()
