# SPDX-License-Identifier: AGPL-3.0-only
import ctypes as C
import hashlib
import json
import os
import random
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
import test_compact_windows_w2 as w2
from compact_windows_w3 import APIS, Code, imported_pe, console_fixture, build, execute, compare, STDOUT, STDERR
from compact_windows_w2 import PREFERRED

class Environment(C.Structure):
    _fields_=[('name',C.c_uint16*64),('value',C.c_uint16*256)]
class Launch(C.Structure):
    _fields_=[('api_mask',C.c_uint32),('console_mask',C.c_uint32),('environment_count',C.c_uint32),('command_line',C.c_uint16*1024),('environment',Environment*16)]
class Allocation(C.Structure):
    _fields_=[('first',C.c_uint32),('pages',C.c_uint32)]
class Services(C.Structure):
    _fields_=[('launch',Launch),('last_error',C.c_uint32),('output_bytes',C.c_uint32*2),('calls',C.c_uint32*9),('output',(C.c_ubyte*65536)*2),('command_bytes',C.c_ubyte*2048),('command_base',C.c_uint64),('heap_base',C.c_uint64),('heap',C.c_void_p),('heap_bytes',C.c_size_t),('owner',C.c_ubyte*256),('protection',C.c_ubyte*256),('allocations',Allocation*16),('bound_machine',C.c_void_p)]

def put_utf16(array,text):
    units=struct.unpack('<'+'H'*(len(text.encode('utf-16le'))//2),text.encode('utf-16le'))
    for i,u in enumerate(units):array[i]=u
    array[len(units)]=0

def launch():
    result=Launch();result.api_mask=511;result.console_mask=3
    put_utf16(result.command_line,'flex.exe --w3-test "two words"')
    result.environment_count=1
    put_utf16(result.environment[0].name,'FLEX_W3_PROBE');put_utf16(result.environment[0].value,'ready')
    return result

class WindowsW3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w2.WindowsW2Tests.setUpClass.__func__(cls)
        cls.w3probe=build(cls.directory/'api-probe')
        cls.lib.cw_attach_services.argtypes=[C.POINTER(w2.Machine),C.POINTER(Services),C.POINTER(Launch),C.c_void_p,C.c_size_t]
        cls.lib.cw_api_dispatch.argtypes=[C.POINTER(w2.Machine)]
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    admitted=w2.WindowsW2Tests.admitted
    loaded=w2.WindowsW2Tests.loaded
    denied=w2.WindowsW2Tests.denied
    mutate=w2.WindowsW2Tests.mutate
    def context(self,config=None,blob=None,heap_size=1024*1024):
        m,arena=self.loaded(blob or imported_pe(b'\xc3',payload=bytes(512)));s=Services();heap=C.create_string_buffer(heap_size or 1);config=config or launch()
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,heap_size),0)
        return m,s,arena,heap
    def api(self,context,name,args=()):
        m,s,arena,heap=context
        m.exited=0;m.status=0;m.r[4]=m.initial_sp-64;m.ip=0xffffffffff000000+APIS.index(name)*16
        for index,value in zip((1,2,8,9),(*args,0,0,0,0)):m.r[index]=value
        self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4],struct.pack('<Q',PREFERRED+0x1000),8),0)
        if name=='WriteFile':self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4]+40,struct.pack('<Q',args[4] if len(args)>4 else 0),8),0)
        status=self.lib.cw_api_dispatch(C.byref(m));self.assertEqual(status,0,(name,status))
        return m.r[0]
    def read(self,ctx,at,n):
        out=C.create_string_buffer(n);self.assertEqual(self.lib.cw_read(C.byref(ctx[0]),at,out,n,1),0);return out.raw
    def write(self,ctx,at,data):self.assertEqual(self.lib.cw_write(C.byref(ctx[0]),at,data,len(data)),0)
    def test_imported_console_program_really_executes_and_exits(self):
        path=self.directory/'console.exe';path.write_bytes(console_fixture());r=execute(self.w3probe,path)
        self.assertEqual(r['status'],0);self.assertEqual(r['stdout_hex'],STDOUT.hex());self.assertEqual(r['exit_code'],37);self.assertEqual(r['exit_kind'],1)
        self.assertEqual(r['api_calls']['WriteFile'],1);self.assertEqual(r['imports'],9)
    def test_default_and_explicitly_missing_api_authority_deny_before_execution(self):
        path=self.directory/'console.exe';path.write_bytes(console_fixture())
        r=execute(self.w3probe,path,api_mask=0);self.assertEqual(r,{'status':10,'executed':False,'allocation_bytes':0})
        m,arena=self.loaded(console_fixture());s=Services();config=launch();config.api_mask=1;heap=C.create_string_buffer(4096)
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,len(heap)),10);self.assertFalse(m.services)
        self.assertNotEqual(self.lib.cw_run(C.byref(m),1000),0);self.assertTrue(arena)
    def test_import_names_ordinals_modules_binding_and_descriptors_fail_closed(self):
        for name in ('writefile','CreateProcessW','NtCreateFile','GetProcAddress'):
            self.denied(imported_pe(b'\xc3',names=(name,)))
        blob=imported_pe(b'\xc3')
        for off,fmt,value in [(0x400+4,'I',1),(0x400+8,'I',1),(0x400+20,'I',1),(0x400+16,'I',0x20a1),(0x440,'Q',0x8000000000000001),(0x440,'Q',0x100000000),(0x4a0,'Q',0),(0x98+112+8,'II',(0x2000,20)),(0x98+112+12*8,'II',(0x20a0,8))]:
            self.denied(self.mutate(off,fmt,value,blob))
        bad=bytearray(blob);bad[0x500:0x50c]=b'ntdll.dll\0\0\0';self.denied(bytes(bad))
        self.denied(imported_pe(b'\xc3',names=('WriteFile','WriteFile')))
    def test_unbound_fallback_lookup_works_and_iat_is_read_only(self):
        blob=self.mutate(0x400,'I',0,imported_pe(b'\xc3'));ctx=self.context(blob=blob)
        self.assertNotEqual(self.lib.cw_write(C.byref(ctx[0]),PREFERRED+0x20a0,b'A',1),0)
        self.assertNotEqual(self.lib.cw_write(C.byref(ctx[0]),PREFERRED+0x209f,b'A'*8,8),0)
        self.assertEqual(struct.unpack('<Q',self.read(ctx,PREFERRED+0x20a0,8))[0],0xffffffffff000000)
    def test_absent_console_handles_and_unrecognized_standard_handle(self):
        config=launch();config.console_mask=0;ctx=self.context(config)
        for n in (-10,-11,-12):self.assertEqual(self.api(ctx,'GetStdHandle',(n&0xffffffff,)),0)
        self.assertEqual(self.api(ctx,'GetStdHandle',(42,)),0xffffffffffffffff);self.assertEqual(self.api(ctx,'GetLastError'),87)
    def test_explicit_console_grants_are_per_machine_and_not_host_paths(self):
        first=self.context();config=launch();config.console_mask=0;second=self.context(config)
        self.assertEqual(self.api(first,'GetStdHandle',(0xfffffff5,)),0x10001)
        self.assertEqual(self.api(second,'GetStdHandle',(0xfffffff5,)),0)
        self.write(first,PREFERRED+0x2400,b'hello');self.write(second,PREFERRED+0x2400,b'hello')
        args=(0x10001,PREFERRED+0x2400,5,PREFERRED+0x2450,0)
        self.assertEqual(self.api(first,'WriteFile',args),1);self.assertEqual(self.api(second,'WriteFile',args),0)
        self.assertEqual(bytes(first[1].output[0][:5]),b'hello');self.assertEqual(second[1].output_bytes[0],0)
    def test_writefile_buffers_and_fifth_argument_validated_without_output(self):
        ctx=self.context();at=PREFERRED+0x2400
        for args,error in [((0x10001,0,4,at+100,0),998),((0x10001,at,4,0,0),87),((0x10001,at,4,PREFERRED+0x1000,0),998),((0x10001,at,4,at+100,1),50),((0x666,at,4,at+100,0),6),((0x10001,at,65537,at+100,0),87)]:
            self.assertEqual(self.api(ctx,'WriteFile',args),0);self.assertEqual(self.api(ctx,'GetLastError'),error);self.assertEqual(ctx[1].output_bytes[0],0)
        self.assertEqual(self.api(ctx,'WriteFile',(0x10001,0,0,at+100,0)),1)
        self.assertEqual(self.read(ctx,at+100,4),bytes(4))
    def test_output_quota_is_aggregate_and_rejection_is_atomic(self):
        ctx=self.context();memory=self.api(ctx,'VirtualAlloc',(0,65536,0x3000,4));self.write(ctx,memory,b'A'*65536);count=PREFERRED+0x2450
        self.assertEqual(self.api(ctx,'WriteFile',(0x10001,memory,65536,count,0)),1)
        self.assertEqual(self.api(ctx,'WriteFile',(0x10002,memory,1,count,0)),0);self.assertEqual(ctx[1].last_error,8)
        self.assertEqual(ctx[1].output_bytes[0],65536);self.assertEqual(ctx[1].output_bytes[1],0);self.assertEqual(self.read(ctx,count,4),bytes(4))
    def test_last_error_is_per_machine_and_dword_sized(self):
        first=self.context();second=self.context()
        self.api(first,'SetLastError',(0x12345678abcdef01,));self.assertEqual(self.api(first,'GetLastError'),0xabcdef01);self.assertEqual(self.api(second,'GetLastError'),0)
        self.api(first,'GetCommandLineW');self.assertEqual(self.api(first,'GetLastError'),0xabcdef01)
    def test_command_line_is_utf16_stable_read_only_and_not_host_arguments(self):
        config=launch();text='flex.exe "ශ්‍රී 😀"';put_utf16(config.command_line,text);ctx=self.context(config)
        at=self.api(ctx,'GetCommandLineW');self.assertEqual(at,self.api(ctx,'GetCommandLineW'));self.assertEqual(self.read(ctx,at,len(text.encode('utf-16le'))+2),text.encode('utf-16le')+b'\0\0')
        self.assertNotEqual(self.lib.cw_write(C.byref(ctx[0]),at,b'A',1),0)
        out=C.create_string_buffer(1);self.assertNotEqual(self.lib.cw_read(C.byref(ctx[0]),at,out,1,4),0)
    def test_environment_query_small_buffer_case_and_unicode_value(self):
        config=launch();value='ශ්‍රී 😀';put_utf16(config.environment[0].value,value);ctx=self.context(config);name=PREFERRED+0x2400;buffer=name+128
        self.write(ctx,name,'flex_w3_probe'.encode('utf-16le')+b'\0\0');units=len(value.encode('utf-16le'))//2
        self.assertEqual(self.api(ctx,'GetEnvironmentVariableW',(name,0,0)),units+1)
        self.write(ctx,buffer,b'Z'*64);self.assertEqual(self.api(ctx,'GetEnvironmentVariableW',(name,buffer,1)),units+1);self.assertEqual(self.read(ctx,buffer,64),b'Z'*64)
        self.assertEqual(self.api(ctx,'GetEnvironmentVariableW',(name,buffer,32)),units);self.assertEqual(self.read(ctx,buffer,(units+1)*2),value.encode('utf-16le')+b'\0\0')
    def test_missing_environment_never_inherits_host_and_bad_pointers_fail(self):
        ctx=self.context();name=PREFERRED+0x2400;self.write(ctx,name,'PATH'.encode('utf-16le')+b'\0\0')
        self.assertEqual(self.api(ctx,'GetEnvironmentVariableW',(name,0,0)),0);self.assertEqual(ctx[1].last_error,203)
        self.assertEqual(self.api(ctx,'GetEnvironmentVariableW',(0,0,0)),0);self.assertEqual(ctx[1].last_error,998)
        self.write(ctx,name,'FLEX_W3_PROBE'.encode('utf-16le')+b'\0\0');self.assertEqual(self.api(ctx,'GetEnvironmentVariableW',(name,PREFERRED+0x1000,16)),0);self.assertEqual(ctx[1].last_error,998)
    def test_reserve_commit_decommit_recommit_and_release(self):
        ctx=self.context();m=ctx[0];out=C.create_string_buffer(1)
        at=self.api(ctx,'VirtualAlloc',(0,8192,0x2000,4));self.assertTrue(at);self.assertEqual(at%65536,0)
        self.assertNotEqual(self.lib.cw_read(C.byref(m),at,out,1,1),0)
        self.assertEqual(self.api(ctx,'VirtualAlloc',(at+3,4096,0x1000,4)),at);self.assertEqual(self.read(ctx,at,8192),bytes(8192))
        self.write(ctx,at,b'A');self.assertEqual(self.api(ctx,'VirtualAlloc',(at,4096,0x1000,4)),at);self.assertEqual(self.read(ctx,at,1),b'A')
        self.assertEqual(self.api(ctx,'VirtualFree',(at,0,0x4000)),1);self.assertNotEqual(self.lib.cw_read(C.byref(m),at,out,1,1),0)
        self.assertEqual(self.api(ctx,'VirtualAlloc',(at,8192,0x1000,4)),at);self.assertEqual(self.read(ctx,at,8192),bytes(8192))
        self.assertEqual(self.api(ctx,'VirtualFree',(at,0,0x8000)),1);self.assertNotEqual(self.lib.cw_read(C.byref(m),at,out,1,1),0)
        self.assertEqual(self.api(ctx,'VirtualFree',(at,0,0x8000)),0)
    def test_heap_protection_no_execute_readonly_and_noaccess(self):
        ctx=self.context();out=C.create_string_buffer(1)
        for protect in (1,2,4):
            at=self.api(ctx,'VirtualAlloc',(0,4096,0x3000,protect));self.assertTrue(at)
            self.assertNotEqual(self.lib.cw_read(C.byref(ctx[0]),at,out,1,4),0)
            self.assertEqual(self.lib.cw_read(C.byref(ctx[0]),at,out,1,1)==0,protect!=1)
            self.assertEqual(self.lib.cw_write(C.byref(ctx[0]),at,b'A',1)==0,protect==4)
        for protect in (0,0x10,0x20,0x40,0x100):self.assertEqual(self.api(ctx,'VirtualAlloc',(0,4096,0x3000,protect)),0)
    def test_allocation_size_addresses_flags_quota_and_double_free(self):
        ctx=self.context(heap_size=65536)
        for args in ((0,0,0x3000,4),(0,65537,0x3000,4),(0,0xffffffffffffffff,0x3000,4),(PREFERRED,4096,0x3000,4),(0,4096,0x8000,4),(1,4096,0x3000,4)):
            self.assertEqual(self.api(ctx,'VirtualAlloc',args),0)
        at=self.api(ctx,'VirtualAlloc',(0,65536,0x3000,4));self.assertTrue(at);self.assertEqual(self.api(ctx,'VirtualAlloc',(0,4096,0x3000,4)),0)
        for args in ((at,1,0x8000),(at+4096,0,0x8000),(at,0,0),(at+65535,2,0x4000)):
            self.assertEqual(self.api(ctx,'VirtualFree',args),0)
        self.assertEqual(self.api(ctx,'VirtualFree',(at,0,0x8000)),1)
        again=self.api(ctx,'VirtualAlloc',(0,65536,0x3000,4));self.assertEqual(again,at);self.assertEqual(self.read(ctx,again,65536),bytes(65536))
    def test_heap_state_and_errors_do_not_leak_between_environments(self):
        first=self.context();second=self.context();at=self.api(first,'VirtualAlloc',(0,4096,0x3000,4));self.write(first,at,b'private')
        out=C.create_string_buffer(7);self.assertNotEqual(self.lib.cw_read(C.byref(second[0]),at,out,7,1),0)
        other=self.api(second,'VirtualAlloc',(0,4096,0x3000,4));self.assertEqual(at,other);self.assertEqual(self.read(second,other,7),bytes(7))
    def test_thunk_forgery_undeclared_apis_and_stack_alignment_fail(self):
        ctx=self.context(blob=imported_pe(b'\xc3',names=('GetLastError',)));m=ctx[0]
        m.ip=0xffffffffff000000;self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),10)
        m.ip=0xffffffffff000001;self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),6)
        m.ip=0xffffffffff000030;m.r[4]=m.initial_sp-1;self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),9)
    def test_launcher_limits_duplicate_names_invalid_utf16_and_authority_fail(self):
        for mutate in (lambda c:setattr(c,'environment_count',17),lambda c:setattr(c,'api_mask',512),lambda c:setattr(c,'console_mask',4),lambda c:c.command_line.__setitem__(0,0xd800)):
            config=launch();mutate(config);m,arena=self.loaded(imported_pe(b'\xc3'));s=Services();heap=C.create_string_buffer(4096)
            self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,4096),10);self.assertFalse(m.services)
        config=launch();config.environment_count=2;put_utf16(config.environment[1].name,'flex_w3_probe');m,arena=self.loaded(imported_pe(b'\xc3'));s=Services();heap=C.create_string_buffer(4096)
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,4096),10)
    def test_normal_unwind_metadata_admitted_but_handlers_and_bad_ranges_denied(self):
        # Runtime-function table plus version-1 PUSH_NONVOL RBX unwind info.
        data=struct.pack('<III',0x1000,0x1001,0x2020)+bytes(20)+bytes([1,1,1,0,1,0x30,0,0])
        blob=self.mutate(0x98+112+3*8,'II',(0x2000,12),w2.pe(b'\xc3',data));self.assertEqual(self.admitted(blob)[0],0)
        for offset,fmt,value in [(0x420,'B',9),(0x420,'B',2),(0x400+4,'I',0x1000),(0x400+8,'I',0xFFFFFFFF),(0x424,'B',2),(0x425,'B',0x40)]:self.denied(self.mutate(offset,fmt,value,blob))
    def test_import_mutation_corpus_remains_bounded_and_does_not_crash(self):
        rng=random.Random(0xC03);original=imported_pe(b'\xc3',payload=bytes(512))
        for _ in range(600):
            blob=bytearray(original)
            for _ in range(rng.randint(1,5)):
                offset=rng.choice((rng.randrange(0x188,0x1d8),rng.randrange(0x400,0x700)))
                blob[offset]=rng.randrange(256)
            status,plan=self.admitted(bytes(blob))
            if status==0:self.assertLessEqual(plan.import_count,9)
    def test_service_backing_aliases_and_reattachment_are_rejected(self):
        m,arena=self.loaded(imported_pe(b'\xc3'));s=Services();config=launch()
        # An image-backed heap would let guest API state alias loaded code/data.
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),arena,4096),10)
        heap=C.create_string_buffer(4096)
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,4096),0)
        config.console_mask=0
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,4096),10)
        self.assertEqual(s.launch.console_mask,3)

    def test_service_state_cannot_be_attached_to_a_second_machine(self):
        first=self.context();m,arena=self.loaded(imported_pe(b'\xc3'));config=launch();config.console_mask=0;heap=C.create_string_buffer(4096)
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(first[1]),C.byref(config),heap,4096),10)
        self.assertFalse(m.services);self.assertEqual(first[1].launch.console_mask,3)
        self.assertEqual(self.api(first,'GetStdHandle',(0xfffffff5,)),0x10001)
        # Even a misconfigured host copying the services pointer cannot borrow authority.
        m.services=C.addressof(first[1]);m.ip=0xffffffffff000000
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),10)
        out=C.create_string_buffer(2)
        self.assertNotEqual(self.lib.cw_read(C.byref(m),first[1].command_base,out,2,1),0)

    def test_reference_provenance_and_execution_cannot_be_forged(self):
        image=self.directory/'comparison.exe';image.write_bytes(console_fixture());receipt=self.directory/'reference.json';output=self.directory/'comparison.json'
        native={'schema':'compact-windows-w3-reference/v1','source_commit':'a'*40,'source_sha256':hashlib.sha256((ROOT/'tests/fixtures/windows_w3_reference.c').read_bytes()).hexdigest(),'executable_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'architecture':'X64','platform':'Microsoft Windows 10.0.20348','native_reference_passed':True,'stdout':STDOUT.decode(),'stderr':STDERR.decode(),'exit_code':0x12345678}
        with patch.dict(os.environ,{'GITHUB_SHA':'a'*40}):
            for key,value in [('source_commit','b'*40),('executable_sha256','0'*64),('source_sha256','0'*64),('platform','Linux'),('stdout','fake'),('exit_code',37),('native_reference_passed',False)]:
                bad=dict(native);bad[key]=value;receipt.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):compare(self.w3probe,image,receipt,output)
            receipt.write_text(json.dumps(native))
            with self.assertRaises(ValueError):compare(self.w3probe,image,receipt,output) # actual guest output/exit differs

if __name__=='__main__':unittest.main()
