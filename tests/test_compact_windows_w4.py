# SPDX-License-Identifier: AGPL-3.0-only
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
import test_compact_windows_w2 as w2
import test_compact_windows_w3 as w3
from compact_windows_w3 import imported_pe,Code
from compact_windows_w4 import ALL_APIS,FILE_APIS,build,execute,compare,PAYLOAD,STDOUT
from compact_windows_w2 import PREFERRED
INVALID=0xffffffffffffffff
FILE_IMPORTS=('WriteFile','GetLastError','ExitProcess',*FILE_APIS)
class Grant(C.Structure):
    _fields_=[('ref',C.c_char*64),('drive',C.c_uint32),('rights',C.c_uint32)]
class Handle(C.Structure):
    _fields_=[('token',C.c_uint64),('resource',C.c_uint64),('position',C.c_uint64),('access',C.c_uint32),('mount',C.c_uint32)]
class Namespace(C.Structure):
    _fields_=[('bound_machine',C.c_void_p),('ops',C.c_void_p),('context',C.c_void_p),('mount_count',C.c_uint32),('serial',C.c_uint32),('mounts',Grant*8),('handles',Handle*30),('scratch',C.c_ubyte*65536)]

class WindowsW4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w3.WindowsW3Tests.setUpClass.__func__(cls)
        host=cls.directory/'host.so'
        subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-pedantic','-O2','-shared','-fPIC','-fsanitize=undefined','-fno-sanitize-recover=all',str(ROOT/'ryzova/compat/windows/files_host.c'),'-o',str(host)],check=True)
        cls.host=C.CDLL(str(host));cls.host.cw_file_host_new.restype=C.c_void_p
        cls.host.cw_file_host_add_root.argtypes=[C.c_void_p,C.c_int]
        cls.host.cw_file_host_ops.restype=C.c_void_p
        cls.host.cw_file_host_destroy.argtypes=[C.c_void_p]
        cls.host.cw_file_host_open_count.argtypes=[C.c_void_p];cls.host.cw_file_host_open_count.restype=C.c_uint32
        cls.lib.cw_attach_files.argtypes=[C.POINTER(w2.Machine),C.POINTER(Namespace),C.POINTER(Grant),C.c_uint32,C.c_void_p,C.c_void_p]
        cls.lib.cw_files_close_all.argtypes=[C.POINTER(w2.Machine)]
        cls.probe4=build(cls.directory/'file-probe')
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    loaded=w2.WindowsW2Tests.loaded
    admitted=w2.WindowsW2Tests.admitted
    read=w3.WindowsW3Tests.read
    write=w3.WindowsW3Tests.write
    def setUp(self):self.resources=[]
    def tearDown(self):
        for ctx in reversed(self.resources):
            self.lib.cw_files_close_all(C.byref(ctx[0]));self.host.cw_file_host_destroy(ctx[5])
    def context(self,rights=31,drive='C',root=None,blob=None,provider=None):
        config=w3.launch();config.api_mask=32767
        m,s,arena,heap=w3.WindowsW3Tests.context(self,config=config,blob=blob or imported_pe(b'\xc3',names=FILE_IMPORTS,payload=bytes(512)))
        # W3 launch enables nine APIs only; W4 requires the additional explicit bits.
        s.launch.api_mask=32767
        if root is None:root=Path(tempfile.mkdtemp(prefix='root-',dir=self.directory))
        root=Path(root);root.mkdir(exist_ok=True)
        host=provider or self.host.cw_file_host_new();fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:index=self.host.cw_file_host_add_root(host,fd)
        finally:os.close(fd)
        ns=Namespace();grant=Grant(ref=b'work',drive=ord(drive),rights=rights)
        # A shared provider's roots have matching index order; this helper uses one mount.
        self.assertEqual(index,0)
        self.assertEqual(self.lib.cw_attach_files(C.byref(m),C.byref(ns),C.byref(grant),1,self.host.cw_file_host_ops(),host),0)
        ctx=(m,s,arena,heap,ns,host,root);self.resources.append(ctx);return ctx
    def api(self,ctx,name,args=()):
        m=ctx[0];m.exited=0;m.status=0;m.r[4]=m.initial_sp-96;m.ip=0xffffffffff000000+ALL_APIS.index(name)*16
        for reg,value in zip((1,2,8,9),(*args,0,0,0,0)):m.r[reg]=value
        self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4],struct.pack('<Q',PREFERRED+0x1000),8),0)
        for i in range(3):
            value=args[4+i] if len(args)>4+i else 0
            self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4]+40+i*8,struct.pack('<Q',value),8),0)
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),0,name);return m.r[0]
    def open(self,ctx,path='payload.bin',access=0xc0000000,mode=1,share=3):
        at=PREFERRED+0x2400;self.write(ctx,at,path.encode('utf-16le')+b'\0\0')
        return self.api(ctx,'CreateFileW',(at,access,share,0,mode,0x80,0))
    def err(self,ctx):return self.api(ctx,'GetLastError')
    def io(self,ctx,name,h,data=b'hello',n=None,overlapped=0):
        buffer=PREFERRED+0x2500;count=PREFERRED+0x25f0
        if name=='WriteFile':self.write(ctx,buffer,data)
        result=self.api(ctx,name,(h,buffer,len(data) if n is None else n,count,overlapped))
        return result,struct.unpack('<I',self.read(ctx,count,4))[0]
    def test_create_write_read_seek_size_flush_and_persistent_bytes(self):
        ctx=self.context();h=self.open(ctx);self.assertNotEqual(h,INVALID)
        self.assertEqual(self.io(ctx,'WriteFile',h,b'hello'),(1,5));self.assertEqual(self.api(ctx,'FlushFileBuffers',(h,)),1)
        result=PREFERRED+0x25e0
        self.assertEqual(self.api(ctx,'GetFileSizeEx',(h,result)),1);self.assertEqual(struct.unpack('<Q',self.read(ctx,result,8))[0],5)
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,0,result,0)),1)
        self.assertEqual(self.io(ctx,'ReadFile',h,n=20),(1,5));self.assertEqual(self.read(ctx,PREFERRED+0x2500,5),b'hello')
        self.assertEqual(self.io(ctx,'ReadFile',h,n=20),(1,0));self.assertEqual(self.api(ctx,'CloseHandle',(h,)),1)
        self.assertEqual((ctx[6]/'payload.bin').read_bytes(),b'hello');self.assertEqual(self.host.cw_file_host_open_count(ctx[5]),0)
    def test_guest_drives_casefold_and_nested_directories(self):
        ctx=self.context();(ctx[6]/'Docs').mkdir();(ctx[6]/'Docs'/'Case.TXT').write_bytes(b'case')
        h=self.open(ctx,'c:\\dOcS\\cAsE.txt',access=0x80000000,mode=3);self.assertNotEqual(h,INVALID)
        self.assertEqual(self.io(ctx,'ReadFile',h,n=8),(1,4));self.assertEqual(self.read(ctx,PREFERRED+0x2500,4),b'case')
        self.assertEqual(self.open(ctx,'D:\\Docs\\Case.txt',access=0x80000000,mode=3),INVALID);self.assertEqual(self.err(ctx),5)
    def test_read_only_grant_denies_destructive_open_create_and_write(self):
        ctx=self.context(rights=9);file=ctx[6]/'keep.bin';file.write_bytes(b'keep')
        for mode in (1,2,4,5):self.assertEqual(self.open(ctx,'keep.bin',mode=mode),INVALID)
        self.assertEqual(file.read_bytes(),b'keep');self.assertFalse((ctx[6]/'new.bin').exists())
        h=self.open(ctx,'keep.bin',access=0x80000000,mode=3);self.assertNotEqual(h,INVALID)
        self.assertEqual(self.io(ctx,'WriteFile',h,b'bad'),(0,0));self.assertEqual(self.err(ctx),5)
    def test_create_right_is_separate_from_existing_file_write(self):
        ctx=self.context(rights=11);(ctx[6]/'old.bin').write_bytes(b'old')
        self.assertEqual(self.open(ctx,'new.bin'),INVALID);self.assertEqual(self.err(ctx),5)
        h=self.open(ctx,'old.bin',mode=3);self.assertNotEqual(h,INVALID);self.assertEqual(self.io(ctx,'WriteFile',h,b'new'),(1,3))
        self.assertEqual((ctx[6]/'old.bin').read_bytes(),b'new')
    def test_all_creation_dispositions_and_last_error(self):
        ctx=self.context();h=self.open(ctx);self.assertEqual(self.io(ctx,'WriteFile',h,b'old'),(1,3));self.api(ctx,'CloseHandle',(h,))
        self.assertEqual(self.open(ctx),INVALID);self.assertEqual(self.err(ctx),80)
        h=self.open(ctx,mode=4);self.assertNotEqual(h,INVALID);self.assertEqual(self.err(ctx),183);self.api(ctx,'CloseHandle',(h,))
        h=self.open(ctx,mode=2);self.assertNotEqual(h,INVALID);self.assertEqual(self.err(ctx),183);self.assertEqual((ctx[6]/'payload.bin').read_bytes(),b'');self.api(ctx,'CloseHandle',(h,))
        self.assertEqual(self.open(ctx,'missing.bin',mode=3),INVALID);self.assertEqual(self.err(ctx),2)
        self.assertEqual(self.open(ctx,'missing.bin',mode=5),INVALID)
        h=self.open(ctx,'new.bin',mode=4);self.assertNotEqual(h,INVALID);self.assertEqual(self.err(ctx),0)
    def test_share_denials_happen_before_truncation_and_release_on_close(self):
        ctx=self.context();h=self.open(ctx,share=0);self.io(ctx,'WriteFile',h,b'preserve')
        self.assertEqual(self.open(ctx,mode=2),INVALID);self.assertEqual(self.err(ctx),32);self.assertEqual((ctx[6]/'payload.bin').read_bytes(),b'preserve')
        self.api(ctx,'CloseHandle',(h,));other=self.open(ctx,mode=2);self.assertNotEqual(other,INVALID)
    def test_read_share_compatibility_and_independent_offsets(self):
        ctx=self.context();(ctx[6]/'payload.bin').write_bytes(b'abc')
        first=self.open(ctx,access=0x80000000,mode=3,share=1);second=self.open(ctx,access=0x80000000,mode=3,share=1)
        self.assertNotEqual(second,INVALID);self.assertEqual(self.io(ctx,'ReadFile',first,n=1),(1,1));self.assertEqual(self.io(ctx,'ReadFile',second,n=1),(1,1));self.assertEqual(self.read(ctx,PREFERRED+0x2500,1),b'a')
        self.assertEqual(self.open(ctx,access=0x40000000,mode=3),INVALID);self.assertEqual(self.err(ctx),32)
    def test_stale_handles_generation_double_close_and_table_quota(self):
        ctx=self.context();first=self.open(ctx);self.assertEqual(self.api(ctx,'CloseHandle',(first,)),1)
        second=self.open(ctx,mode=3);self.assertNotEqual(first,second);self.assertEqual(self.api(ctx,'CloseHandle',(first,)),0);self.assertEqual(self.err(ctx),6)
        self.assertEqual(self.io(ctx,'ReadFile',first,n=1),(0,0));handles=[second]
        for _ in range(29):handles.append(self.open(ctx,mode=3))
        self.assertTrue(all(h!=INVALID for h in handles));self.assertEqual(self.open(ctx,'quota.bin'),INVALID);self.assertEqual(self.err(ctx),4);self.assertFalse((ctx[6]/'quota.bin').exists())
    def test_namespace_isolation_and_copied_context_cannot_borrow_authority(self):
        first=self.context();second=self.context();h=self.open(first);self.io(first,'WriteFile',h,b'private')
        self.assertEqual(self.io(second,'ReadFile',h,n=7),(0,0));self.assertFalse((second[6]/'payload.bin').exists())
        original=second[1].files;second[1].files=C.addressof(first[4]);self.assertEqual(self.open(second),INVALID);second[1].files=original
        self.assertEqual((first[6]/'payload.bin').read_bytes(),b'private')
    def test_traversal_unc_device_ads_and_ambiguous_paths_are_denied(self):
        ctx=self.context()
        paths=('..\\escape','a\\..\\escape','.\\file','/etc/passwd','\\outside','\\\\server\\share','\\\\?\\C:\\x','C:relative','C:/x','C:\\x:stream','con','NUL.txt','com1.log','lpt9','x.','x ','a\\\\b','a/./b','a~1.txt','a*','a?','ශ්‍රී','a'*64,'a/'*17+'b')
        for path in paths:
            with self.subTest(path=path):self.assertEqual(self.open(ctx,path),INVALID);self.assertEqual(self.err(ctx),123)
        self.assertEqual(list(ctx[6].iterdir()),[])
    def test_symlink_hardlink_directory_link_and_special_files_cannot_escape(self):
        ctx=self.context();outside=self.directory/'outside-secret';outside.write_bytes(b'secret')
        (ctx[6]/'link').symlink_to(outside);os.link(outside,ctx[6]/'hard')
        directory=self.directory/'outside-dir';directory.mkdir(exist_ok=True);(directory/'file').write_bytes(b'outside')
        (ctx[6]/'dirlink').symlink_to(directory,target_is_directory=True);os.mkfifo(ctx[6]/'pipe')
        for path in ('link','hard','dirlink/file','pipe'):
            self.assertEqual(self.open(ctx,path,mode=2),INVALID,path)
        self.assertEqual(outside.read_bytes(),b'secret');self.assertEqual((directory/'file').read_bytes(),b'outside')
    def test_case_collision_and_directory_scan_limit_fail_closed(self):
        ctx=self.context();(ctx[6]/'Alpha').write_bytes(b'1');(ctx[6]/'ALPHA').write_bytes(b'2')
        self.assertEqual(self.open(ctx,'alpha',mode=2),INVALID);self.assertEqual(self.err(ctx),123)
        for i in range(256):(ctx[6]/('entry'+str(i))).touch()
        self.assertEqual(self.open(ctx,'new.bin'),INVALID);self.assertEqual(self.err(ctx),8)
    def test_pointer_validation_prevents_file_position_or_content_changes(self):
        ctx=self.context();h=self.open(ctx);self.io(ctx,'WriteFile',h,b'keep')
        bad=PREFERRED+0x1000;count=PREFERRED+0x25f0
        self.assertEqual(self.api(ctx,'ReadFile',(h,bad,4,count,0)),0);self.assertEqual(self.err(ctx),998)
        self.assertEqual(self.api(ctx,'GetFileSizeEx',(h,bad)),0);self.assertEqual(self.err(ctx),998)
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,0,bad,0)),0);self.assertEqual(ctx[4].handles[0].position,4)
        self.assertEqual(self.api(ctx,'WriteFile',(h,bad,1,0,0)),0);self.assertEqual((ctx[6]/'payload.bin').read_bytes(),b'keep')
    def test_signed_seek_gap_zero_fill_eof_and_file_cap(self):
        ctx=self.context();h=self.open(ctx);self.io(ctx,'WriteFile',h,b'abc')
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,(-2)&INVALID,0,2)),1);self.assertEqual(ctx[4].handles[0].position,1)
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,(-4)&INVALID,0,0)),0);self.assertEqual(self.err(ctx),131)
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,6,0,0)),1);self.io(ctx,'WriteFile',h,b'!');self.assertEqual((ctx[6]/'payload.bin').read_bytes(),b'abc\0\0\0!')
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,65536,0,0)),1);self.assertEqual(self.io(ctx,'WriteFile',h,b'x'),(0,0));self.assertEqual(self.err(ctx),223)
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,0x7fffffffffffffff,0,1)),0)
    def test_metadata_rights_zero_access_handles_and_flush_types(self):
        ctx=self.context(rights=3);(ctx[6]/'payload.bin').write_bytes(b'a');h=self.open(ctx,mode=3)
        self.assertEqual(self.api(ctx,'GetFileSizeEx',(h,PREFERRED+0x25e0)),0);self.assertEqual(self.err(ctx),5)
        self.assertEqual(self.api(ctx,'SetFilePointerEx',(h,0,0,2)),0)
        self.assertEqual(self.api(ctx,'FlushFileBuffers',(0x10001,)),0);self.assertEqual(self.err(ctx),6)
        meta=self.context(rights=8);(meta[6]/'payload.bin').write_bytes(b'm');h=self.open(meta,access=0,mode=3)
        self.assertNotEqual(h,INVALID);self.assertEqual(self.api(meta,'GetFileSizeEx',(h,PREFERRED+0x25e0)),1);self.assertEqual(self.io(meta,'ReadFile',h,n=1),(0,0))
    def test_handle_closure_on_exit_budget_and_opcode_failure(self):
        for code,budget in ((b'\xc3',100),(b'\xeb\xfe',20),(b'\x0f\x0b',100)):
            ctx=self.context(blob=imported_pe(code,names=FILE_IMPORTS,payload=bytes(512)));self.open(ctx)
            self.assertEqual(self.host.cw_file_host_open_count(ctx[5]),1)
            ctx[0].ip=PREFERRED+0x1000;ctx[0].r[4]=ctx[0].initial_sp
            self.lib.cw_run(C.byref(ctx[0]),budget);self.assertEqual(self.host.cw_file_host_open_count(ctx[5]),0)
        ctx=self.context();self.open(ctx);self.api(ctx,'ExitProcess',(37,));self.assertEqual(self.host.cw_file_host_open_count(ctx[5]),0)
    def test_close_console_handle_preserves_policy_but_invalidates_io(self):
        ctx=self.context();self.assertEqual(self.api(ctx,'CloseHandle',(0x10001,)),1)
        self.assertEqual(self.api(ctx,'CloseHandle',(0x10001,)),0);self.assertEqual(self.err(ctx),6)
        self.assertEqual(self.io(ctx,'WriteFile',0x10001,b'x'),(0,0));self.assertEqual(ctx[1].launch.console_mask,3)
    def test_file_flags_security_attributes_and_overlapped_io_are_refused(self):
        ctx=self.context();at=PREFERRED+0x2400;self.write(ctx,at,'payload.bin'.encode('utf-16le')+b'\0\0')
        for access,share,security,mode,flags,template in ((1,3,0,1,0x80,0),(0xc0000000,4,0,1,0x80,0),(0xc0000000,3,1,1,0x80,0),(0xc0000000,3,0,0,0x80,0),(0xc0000000,3,0,1,0x40000000,0),(0xc0000000,3,0,1,0x80,1)):
            self.assertEqual(self.api(ctx,'CreateFileW',(at,access,share,security,mode,flags,template)),INVALID)
        h=self.open(ctx);self.assertEqual(self.io(ctx,'ReadFile',h,n=1,overlapped=1),(0,0));self.assertEqual(self.err(ctx),50)
    def test_large_external_file_is_not_truncated_to_hide_quota_violation(self):
        ctx=self.context();file=ctx[6]/'big';file.write_bytes(b'X'*65537)
        self.assertEqual(self.open(ctx,'big',mode=2),INVALID);self.assertEqual(self.err(ctx),223);self.assertEqual(file.stat().st_size,65537)
    def test_namespace_binding_and_grant_validation(self):
        ctx=self.context();ns=Namespace();grant=Grant(ref=b'../host',drive=ord('C'),rights=31)
        self.assertEqual(self.lib.cw_attach_files(C.byref(ctx[0]),C.byref(ns),C.byref(grant),1,self.host.cw_file_host_ops(),ctx[5]),10)
        other=w3.WindowsW3Tests.context(self,blob=imported_pe(b'\xc3',payload=bytes(512)))
        self.assertEqual(self.lib.cw_attach_files(C.byref(other[0]),C.byref(ctx[4]),C.byref(grant),1,self.host.cw_file_host_ops(),ctx[5]),10)
    def test_explicitly_shared_provider_enforces_sharing_between_namespaces(self):
        first=self.context();h=self.open(first,share=0);self.io(first,'WriteFile',h,b'shared')
        config=w3.launch();config.api_mask=32767
        m,s,arena,heap=w3.WindowsW3Tests.context(self,config=config,blob=imported_pe(b'\xc3',names=FILE_IMPORTS,payload=bytes(512)))
        ns=Namespace();grant=Grant(ref=b'explicit_shared',drive=ord('C'),rights=31)
        self.assertEqual(self.lib.cw_attach_files(C.byref(m),C.byref(ns),C.byref(grant),1,self.host.cw_file_host_ops(),first[5]),0)
        second=(m,s,arena,heap,ns,first[5],first[6])
        try:
            self.assertEqual(self.open(second,mode=2),INVALID);self.assertEqual(self.err(second),32)
            self.assertEqual((first[6]/'payload.bin').read_bytes(),b'shared')
            self.api(first,'CloseHandle',(h,));h2=self.open(second,access=0x80000000,mode=3)
            self.assertNotEqual(h2,INVALID);self.assertEqual(self.io(second,'ReadFile',h2,n=8),(1,6))
        finally:self.lib.cw_files_close_all(C.byref(m))
    def test_nondefault_drive_and_invalid_grants_have_no_implicit_c_root(self):
        ctx=self.context(drive='D');self.assertEqual(self.open(ctx),INVALID)
        self.assertNotEqual(self.open(ctx,'D:\\payload.bin'),INVALID)
        config=w3.launch();config.api_mask=32767
        m,s,arena,heap=w3.WindowsW3Tests.context(self,config=config,blob=imported_pe(b'\xc3',names=FILE_IMPORTS,payload=bytes(512)))
        for ref,drive,rights in ((b'../host',ord('C'),31),(b'C:/host',ord('C'),31),(b'work',0,31),(b'work',ord('C'),32),(b'work',ord('C'),0)):
            ns=Namespace();grant=Grant(ref=ref,drive=drive,rights=rights)
            self.assertEqual(self.lib.cw_attach_files(C.byref(m),C.byref(ns),C.byref(grant),1,self.host.cw_file_host_ops(),ctx[5]),10)
            self.assertFalse(s.files)

    def test_reference_receipt_wrong_source_root_or_result_is_rejected(self):
        image=self.directory/'fake.exe';image.write_bytes(imported_pe(b'\xc3'));receipt=self.directory/'fake.json';out=self.directory/'out.json';root=self.directory/'compare-root';root.mkdir(exist_ok=True)
        native={'schema':'compact-windows-w4-reference/v1','source_commit':'a'*40,'source_sha256':hashlib.sha256((ROOT/'tests/fixtures/windows_w4_reference.c').read_bytes()).hexdigest(),'executable_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'architecture':'X64','platform':'Microsoft Windows 10.0.20348','native_reference_passed':True,'stdout':STDOUT.decode(),'stderr':'','exit_code':0x23456789,'file_sha256':hashlib.sha256(PAYLOAD).hexdigest()}
        with patch.dict(os.environ,{'GITHUB_SHA':'a'*40}):
            for key,value in [('file_sha256','0'*64),('source_commit','b'*40),('platform','Linux'),('stdout','fake')]:
                bad=dict(native);bad[key]=value;receipt.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):compare(self.probe4,image,receipt,root,out)
            receipt.write_text(json.dumps(native));(root/'existing').touch()
            with self.assertRaises(ValueError):compare(self.probe4,image,receipt,root,out)

if __name__=='__main__':unittest.main()
