# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from phase9_process import FLAGS
import phase9_symlinks as gate
from phase9_shell import DIGEST
from test_phase9_persistence import seal,records
CASES=('basic','nofollow','loops','at','rename','times','grants','trailing','boundary','permissions','trailing-mutations')
class SymlinkTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
  cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
  cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
  cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
  subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
  subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_symlinks.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def run_guest(self,mode,*flags,runner=None,env=None):
  return subprocess.run([str(runner or self.runner),*map(str,flags),'-x',str(self.fixture),str(self.fixture),'/tmp/links',mode,'challenge'],capture_output=True,timeout=20,env=env)
 def check_guest(self,mode,*flags,**kwargs):
  result=self.run_guest(mode,*flags,**kwargs);self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(result.stdout,f'FLEX_SYMLINK_OK {mode}\nchallenge\n'.encode());return result
 def test_linux_differential_paths_metadata_errors_and_lifetimes(self):
  for mode in CASES:
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
    vm=self.check_guest(mode)
    native=subprocess.run([str(self.fixture),directory+'/links',mode,'challenge'],capture_output=True,timeout=20)
    self.assertEqual(native.returncode,0,native.stderr);self.assertEqual(vm.stdout,native.stdout)
 def test_snapshot_preserves_relative_chains_directories_and_dangling_links(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';self.check_guest('create','-W',path);self.assertEqual(path.read_bytes()[:8],b'FLEXFS2\n');self.check_guest('reload','-R',path)
 def test_malformed_link_snapshots_never_launch_guest(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';bad=Path(directory)/'bad';out=Path(directory)/'out';self.check_guest('create','-W',path);data=path.read_bytes()
   link=next(at for at in records(data) if struct.unpack_from('<I',data,at+12)[0]==2);name_length=struct.unpack_from('<I',data,link+28)[0]
   mutations=[]
   for at,value in ((link+12,struct.pack('<I',3)),(link+80+name_length,b'\x00'),(0,b'FLEXFS1\n')):
    changed=bytearray(data);changed[at:at+len(value)]=value;mutations.append(seal(changed))
   size,name=struct.unpack_from('<II',data,link+24);at=link+80+name
   for target in (b'',b'x'*256):
    changed=bytearray(data[:at]+target+data[at+size:]);struct.pack_into('<I',changed,link+24,len(target));struct.pack_into('<Q',changed,8,len(changed));mutations.append(seal(changed))
   for value in mutations:
    bad.write_bytes(value);result=self.run_guest('reload','-R',bad,'-W',out)
    self.assertEqual(result.returncode,2,result.stderr);self.assertIn(b'status=1 ',result.stderr);self.assertEqual(result.stdout,b'');self.assertFalse(out.exists())
 def test_saved_link_cannot_override_explicit_immutable_grant(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';self.check_guest('create','-W',path)
   self.check_guest('shadow','-R',path,'-x','/tmp/links/link='+str(self.fixture))
 def test_legacy_snapshot_import_remains_supported(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state';self.check_guest('nofollow','-W',path);data=bytearray(path.read_bytes());self.assertTrue(all(struct.unpack_from('<I',data,at+12)[0]!=2 for at in records(data)));data[:8]=b'FLEXFS1\n';path.write_bytes(seal(data))
   self.check_guest('legacy','-R',path)
 def test_native_gate_requires_all_application_challenges_and_independent_reload(self):
  commit='a'*40;digest='b'*64;digests={'symlinks.elf':digest,'symlinks-script':hashlib.sha256(gate.SCRIPT).hexdigest()}
  lines=['symlinks=guest-paths,40-hop-limit','format=FLEXFS2 import=FLEXFS1,FLEXFS2',digest+'  /tmp/sl-elf',digests['symlinks-script']+'  /tmp/sl-script']
  lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]
  result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10';lines += ['FLEX_SYMLINK_BEGIN']
  for mode in gate.CASES:lines += ['FLEX_SYMLINK_OK '+mode,'S_'+mode+'_'+commit,result,'FLEX_SYMLINK_'+mode+'_RUN_OK']
  for mode,marker in (('create','SAVE'),('reload','RELOAD')):lines += ['FLEX_SYMLINK_OK '+mode,'S_saved_'+commit,result,'FLEX_SYMLINK_'+marker+'_OK']
  lines += ['FLEX_SYMLINK_OK shadow','S_shadow_'+commit,result,'FLEX_SYMLINK_SHADOW_OK']
  lines += ['linked-content','sub/file','linked-content','linked-content','FLEX_SYMLINK_SHELL_OK',result,'FLEX_SYMLINK_SHELL_RUN_OK','FLEX_SYMLINK_END','FLEX_SYMLINK_DONE']
  serial=('\n'.join(lines)+'\n').encode();self.assertTrue(gate.inspect(serial,commit,digests)['passed'])
  for token in ('FLEX_SYMLINK_DONE','FLEX_SYMLINK_RELOAD_OK','S_at_'+commit,'FLEX_SYMLINK_SHELL_OK',digest,'linked-content','symlinks=guest-paths,40-hop-limit'):
   self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
  self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed'])
  self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))
 @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'),'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
 def test_unmodified_busybox_link_copy_read_and_recursive_remove(self):
  busybox=(ROOT/os.environ['COMPACT_SHELL_DIR']/'busybox').resolve();self.assertEqual(hashlib.sha256(busybox.read_bytes()).hexdigest(),DIGEST)
  script=self.directory/'script';script.write_bytes(gate.SCRIPT)
  result=subprocess.run([str(self.runner),'-b','4194304','-x','/busybox','-i',str(script),str(busybox),'ash','/input'],capture_output=True,timeout=20)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'linked-content\nsub/file\nlinked-content\nlinked-content\nFLEX_SYMLINK_SHELL_OK\n')
 def test_address_undefined_and_leak_checks(self):
  runner=self.directory/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
  env=dict(os.environ)
  if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
  for mode in CASES:self.check_guest(mode,runner=runner,env=env)
if __name__=='__main__':unittest.main()
