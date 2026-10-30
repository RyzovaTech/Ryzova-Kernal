# SPDX-License-Identifier: AGPL-3.0-only
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
import phase9_persistence as gate

def seal(data):
    data=bytearray(data);h=14695981039346656037
    for value in data[:-8]:h=((h^value)*1099511628211)&((1<<64)-1)
    struct.pack_into('<Q',data,len(data)-8,h);return bytes(data)
def records(data):
    out=[];at=40
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        out.append(at);n,length=struct.unpack_from('<II',data,at+24);at+=80+n+length
    return out
class PersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name);core=ROOT/'ryzova/compat/linux'
        cls.sources=[str(core/(n+'.c')) for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
        cls.flags=['cc','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=undefined','-fno-sanitize-recover=all']
        cls.runner=cls.directory/'runner';cls.fixture=cls.directory/'fixture'
        subprocess.run([*cls.flags,*cls.sources,'-o',str(cls.runner)],check=True,capture_output=True)
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_persistence.c'),'-o',str(cls.fixture)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def run_guest(self,mode,*flags,challenge='challenge',runner=None,env=None):
        return subprocess.run([str(runner or self.runner),*map(str,flags),str(self.fixture),mode,challenge],env=env,capture_output=True,timeout=10)
    def check(self,mode,*flags,**kwargs):
        result=self.run_guest(mode,*flags,**kwargs);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,f'FLEX_PERSISTENCE_OK {mode}\n{kwargs.get("challenge","challenge")}\n'.encode());return result
    def test_create_reload_append_rename_delete_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            a,b,c=[Path(directory)/name for name in ('one','two','three')]
            self.check('create','-W',a);original=a.read_bytes();self.assertEqual(a.stat().st_mode&0o777,0o600)
            self.check('verify','-R',a);self.check('append','-R',a,'-W',b)
            self.check('verify','-R',b,challenge='challenge!');self.check('rename','-R',b,'-W',c);self.check('empty','-R',c)
            self.assertEqual(a.read_bytes(),original)
            result=self.run_guest('verify');self.assertEqual(result.returncode,2)
    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state';path.write_bytes(b'keep')
            result=self.run_guest('create','-W',path);self.assertEqual(result.returncode,65);self.assertEqual(path.read_bytes(),b'keep')
    def test_guest_fault_still_exports_completed_filesystem_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state';result=self.run_guest('fault','-W',path)
            self.assertEqual(result.returncode,2);self.assertIn(b'status=4 ',result.stderr);self.check('verify','-R',path)
    def test_corruption_topology_duplicate_names_and_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'good';bad=Path(directory)/'bad';output=Path(directory)/'out';self.check('create','-W',path)
            data=path.read_bytes();offsets=records(data);self.assertEqual(len(offsets),3)
            changes=[(0,b'BADMAGIC'),(20,struct.pack('<I',1)),(offsets[1]+4,struct.pack('<I',1)),(offsets[2]+4,struct.pack('<I',2)),(offsets[2]+16,struct.pack('<Q',2000)),(offsets[2]+80,b'../x'),(offsets[1]+12,struct.pack('<I',0)),(offsets[2]+8,struct.pack('<I',0o1777)),(offsets[2]+40,struct.pack('<Q',1000000000)),(offsets[1],struct.pack('<I',32)),(24,struct.pack('<Q',2000)),(offsets[2]+24,struct.pack('<I',65537))]
            mutations=[data[:-1],data+b'x',bytes([data[0]^1])+data[1:]]
            for at,value in changes:
                changed=bytearray(data);changed[at:at+len(value)]=value;mutations.append(seal(changed))
            # Duplicate sibling path while keeping unique inode and valid CRC.
            changed=bytearray(data);changed[offsets[1]+80:offsets[1]+85]=b'data';struct.pack_into('<I',changed,offsets[1]+28,4);struct.pack_into('<Q',changed,8,len(changed));struct.pack_into('<I',changed,offsets[2]-1+4,0);mutations.append(seal(changed))
            for i,value in enumerate(mutations):
                with self.subTest(mutation=i):
                    bad.write_bytes(value);result=self.run_guest('empty','-R',bad,'-W',output)
                    self.assertEqual(result.returncode,2,result.stderr);self.assertIn(b'status=1 ',result.stderr);self.assertEqual(result.stdout,b'');self.assertFalse(output.exists())
    def test_native_gate_requires_complete_reload_challenges_and_corruption_denial(self):
        commit='a'*40;digest='b'*64;result='COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        lines=['linux-amd64-filesystem-snapshot-v1',digest+'  /tmp/ps-elf']+[f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit),gate.start(commit)+len(gate.commands(commit))-1)]+['FLEX_PERSISTENCE_BEGIN']
        for mode,marker,extra in (('create','CREATE',''),('verify','VERIFY',''),('append','APPEND',''),('verify','APPENDED','!'),('rename','RENAME',''),('empty','EMPTY','')):
            lines += ['FLEX_PERSISTENCE_OK '+mode,'P_'+commit+extra,result,'FLEX_PERSIST_'+marker+'_OK']
        lines += ['COMPACT_LINUX_RESULT status=1 exited=0 exit=0 steps=0 syscalls=0','FLEX_PERSIST_CORRUPT_DENIED','FLEX_PERSISTENCE_END','FLEX_PERSISTENCE_DONE']
        serial=('\n'.join(lines)+'\n').encode();digests={'persistence.elf':digest}
        self.assertTrue(gate.inspect(serial,commit,digests)['passed'])
        for token in ('FLEX_PERSISTENCE_DONE','FLEX_PERSIST_VERIFY_OK','P_'+commit+'!',digest,'FLEX_PERSIST_CORRUPT_DENIED'):
            self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING'),commit,digests)['passed'])
        self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed'])
        self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))
    def test_address_undefined_and_leak_checks(self):
        runner=self.directory/'asan';subprocess.run([*self.flags,'-fsanitize=address,undefined','-no-pie',*self.sources,'-o',str(runner)],check=True,capture_output=True)
        env=dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN')=='1':env['ASAN_OPTIONS']='detect_leaks=0:quarantine_size_mb=32'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state';self.check('create','-W',path,runner=runner,env=env);self.check('verify','-R',path,runner=runner,env=env)
            bad=bytearray(path.read_bytes());bad[0]^=1;corrupt=Path(directory)/'bad';corrupt.write_bytes(bad)
            result=self.run_guest('empty','-R',corrupt,runner=runner,env=env);self.assertEqual(result.returncode,2);self.assertNotIn(b'AddressSanitizer',result.stderr)
if __name__=='__main__':unittest.main()
