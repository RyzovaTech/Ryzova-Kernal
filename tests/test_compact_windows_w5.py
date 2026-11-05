# SPDX-License-Identifier: AGPL-3.0-only
import ctypes as C
import json
import os
from pathlib import Path
import random
import struct
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
import test_compact_windows_w2 as w2
import test_compact_windows_w3 as w3
import test_compact_windows_w1 as w1
sys.path.insert(0,str(ROOT))
from ryzova.compat.windows.contract_v1 import validate_request,ContractError
from compact_windows_w2 import pe,PREFERRED
from compact_windows_w5 import ALL_APIS,CRT_APIS,WORKLOADS,imported_pe_modules,build,execute,compare
MASK=(1<<64)-1
class WindowsW5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w3.WindowsW3Tests.setUpClass.__func__(cls);cls.w5probe=build(cls.directory/'w5-probe')
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    loaded=w2.WindowsW2Tests.loaded
    admitted=w2.WindowsW2Tests.admitted
    denied=w2.WindowsW2Tests.denied
    read=w3.WindowsW3Tests.read
    write=w3.WindowsW3Tests.write
    def context(self):
        config=w3.launch();config.api_mask=(1<<28)-1
        blob=imported_pe_modules(b'\xc3',{'kernel32.dll':('VirtualAlloc','VirtualFree','SetLastError','GetLastError'),'ucrtbase.dll':CRT_APIS},bytes(512))
        return w3.WindowsW3Tests.context(self,config=config,blob=blob)
    def api(self,ctx,name,args=(),status=0):
        m=ctx[0];m.ip=0xffffffffff000000+ALL_APIS.index(name)*16;m.r[4]=m.initial_sp-64
        for r,v in zip((1,2,8,9),(*args,0,0,0,0)):m.r[r]=v
        self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4],struct.pack('<Q',PREFERRED+0x1000),8),0)
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),status,name);return m.r[0]
    def cpu(self,code,regs=None,budget=1000):
        m,arena=self.loaded(pe(bytes.fromhex(code) if isinstance(code,str) else code))
        for r,v in (regs or {}).items():m.r[r]=v&MASK
        self.lib.cw_run(C.byref(m),budget);return m,arena
    def test_profile_is_finite_and_matches_the_suite(self):
        d=json.loads((ROOT/'ryzova/compat/windows/w5-profile.json').read_text());self.assertEqual(d['workloads'],WORKLOADS);self.assertEqual(d['crt_exports'],list(CRT_APIS));self.assertIn('SEH dispatch/unwind',d['exclusions'])
    def test_crt_contract_requires_explicit_profile_and_minor_one(self):
        request=w1.request();request['apis']=['UCRTBASE.DLL!malloc']
        with self.assertRaises(ContractError):validate_request(request)
        request['profile']='console-ucrt-selected-v1'
        with self.assertRaises(ContractError):validate_request(request)
        request['api_minor']=1;result=validate_request(request)
        self.assertEqual(result['request']['apis'],['ucrtbase.dll!malloc']);self.assertFalse(result['authority_attached']);self.assertFalse(result['execution_available'])
        request['api_minor']=2
        with self.assertRaises(ContractError):validate_request(request)
    def test_profile_does_not_advertise_unimplemented_crt_exports(self):
        request=w1.request();request.update(profile='console-ucrt-selected-v1',api_minor=1)
        for name in ('printf','fopen','strtol','system','exit'):
            request['apis']=['ucrtbase.dll!'+name]
            with self.assertRaises(ContractError):validate_request(request)

    def test_two_modules_resolve_only_their_own_explicit_exports(self):
        ctx=self.context();self.assertEqual(ctx[0].plan.import_count,17)
        for module,name in [('kernel32.dll','malloc'),('ucrtbase.dll','WriteFile'),('msvcrt.dll','malloc'),('api-ms-win-crt-heap-l1-1-0.dll','malloc')]:self.denied(imported_pe_modules(b'\xc3',{module:(name,)}))
        self.denied(imported_pe_modules(b'\xc3',{'KERNEL32.DLL':('GetLastError',),'kernel32.dll':('SetLastError',)}))
    def test_crt_calls_need_launch_permission_and_iat_is_immutable(self):
        blob=imported_pe_modules(b'\xc3',{'ucrtbase.dll':('strlen',)})
        m,arena=self.loaded(blob);s=w3.Services();config=w3.launch();heap=C.create_string_buffer(4096)
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(config),heap,4096),10)
        ctx=self.context();self.assertNotEqual(self.lib.cw_write(C.byref(ctx[0]),PREFERRED+0x2280,b'X',1),0)
    def test_memcpy_memmove_memset_and_comparison_signs(self):
        ctx=self.context();a=PREFERRED+0x2c00;b=a+128
        self.write(ctx,a,b'abcdefgh\0');self.assertEqual(self.api(ctx,'memcpy',(b,a,9)),b);self.assertEqual(self.read(ctx,b,9),b'abcdefgh\0')
        self.assertEqual(self.api(ctx,'memmove',(a+2,a,8)),a+2);self.assertEqual(self.read(ctx,a,10),b'ababcdefgh')
        self.assertEqual(self.api(ctx,'memset',(b,0x123,4)),b);self.assertEqual(self.read(ctx,b,4),b'####')
        self.write(ctx,a,b'\x00');self.write(ctx,b,b'\xff');self.assertGreaterEqual(self.api(ctx,'memcmp',(a,b,1)),1<<31)
    def test_crt_buffer_failures_are_atomic_and_do_not_forward_to_host(self):
        ctx=self.context();a=PREFERRED+0x2c00;self.write(ctx,a,b'keepme')
        self.api(ctx,'memcpy',(a,0,4),status=12);self.assertEqual(self.read(ctx,a,6),b'keepme')
        self.api(ctx,'memcpy',(a+1,a,4),status=12);self.assertEqual(self.read(ctx,a,6),b'keepme')
        self.api(ctx,'memset',(PREFERRED+0x1000,0,1),status=12)
        self.api(ctx,'memcmp',(0,0,65537),status=12)
        self.assertEqual(self.api(ctx,'memmove',(0,0,0)),0);self.assertEqual(self.api(ctx,'memcmp',(0,0,0)),0)
    def test_string_and_utf16_lengths_comparison_and_bounds(self):
        ctx=self.context();a=PREFERRED+0x2c00;b=a+128;self.write(ctx,a,b'alpha\0');self.write(ctx,b,b'alpine\0')
        self.assertEqual(self.api(ctx,'strlen',(a,)),5);self.assertEqual(self.api(ctx,'strncmp',(a,b,3)),0)
        self.assertGreaterEqual(self.api(ctx,'strcmp',(a,b)),1<<31);self.assertEqual(self.api(ctx,'strncmp',(0,0,0)),0)
        wide='ශ්‍රී😀'.encode('utf-16le');self.write(ctx,b,wide+b'\0\0');self.assertEqual(self.api(ctx,'wcslen',(b,)),len(wide)//2)
        self.api(ctx,'strlen',(0,),status=12);self.api(ctx,'strncmp',(a,b,65537),status=12)
        at=self.api(ctx,'malloc',(65536,));self.write(ctx,at,b'X'*65536);self.api(ctx,'strlen',(at,),status=12)
    def test_malloc_calloc_realloc_preservation_and_free(self):
        ctx=self.context();a=self.api(ctx,'malloc',(16,));self.assertTrue(a);self.write(ctx,a,b'hello\0')
        b=self.api(ctx,'realloc',(a,8192));self.assertTrue(b);self.assertNotEqual(a,b);self.assertEqual(self.read(ctx,b,6),b'hello\0')
        self.assertEqual(self.api(ctx,'realloc',(b,8)),b);self.api(ctx,'free',(b,))
        out=C.create_string_buffer(1);self.assertNotEqual(self.lib.cw_read(C.byref(ctx[0]),b,out,1,1),0)
        zero=self.api(ctx,'calloc',(8,4));self.assertEqual(self.read(ctx,zero,32),bytes(32));self.api(ctx,'free',(zero,));self.api(ctx,'free',(0,))
    def test_errno_is_private_guest_memory_and_independent_of_last_error(self):
        first=self.context();second=self.context();at=self.api(first,'_errno');self.api(first,'SetLastError',(77,))
        self.assertEqual(self.api(first,'calloc',(MASK,2)),0);self.assertEqual(struct.unpack('<I',self.read(first,at,4))[0],12)
        self.assertEqual(self.api(first,'GetLastError'),77);other=self.api(second,'_errno');self.assertEqual(self.read(second,other,4),bytes(4))
        self.write(first,at,struct.pack('<I',22));self.assertEqual(first[1].errno_bytes[0],22)
        out=C.create_string_buffer(1);self.assertNotEqual(self.lib.cw_read(C.byref(first[0]),at,out,1,4),0)
    def test_heap_oom_leaves_realloc_original_valid_and_zero_size_forms(self):
        ctx=self.context();a=self.api(ctx,'malloc',(32,));self.write(ctx,a,b'keep')
        self.assertEqual(self.api(ctx,'realloc',(a,MASK)),0);self.assertEqual(self.read(ctx,a,4),b'keep')
        self.assertEqual(self.api(ctx,'realloc',(a,0)),0);b=self.api(ctx,'realloc',(0,64));self.assertTrue(b);self.api(ctx,'free',(b,))
        z=self.api(ctx,'malloc',(0,));self.assertTrue(z);self.api(ctx,'free',(z,))
        blocks=[self.api(ctx,'malloc',(1,)) for _ in range(16)];self.assertTrue(all(blocks));self.assertEqual(self.api(ctx,'malloc',(1,)),0)
    def test_invalid_free_and_win32_crt_ownership_are_kept_separate(self):
        ctx=self.context();a=self.api(ctx,'malloc',(32,));self.api(ctx,'free',(a+1,),status=12)
        self.assertEqual(self.api(ctx,'VirtualFree',(a,0,0x8000)),0)
        self.assertEqual(self.api(ctx,'VirtualAlloc',(a,4096,0x1000,4)),0)
        self.api(ctx,'free',(a,));self.api(ctx,'free',(a,),status=12)
        v=self.api(ctx,'VirtualAlloc',(0,4096,0x3000,4));self.api(ctx,'free',(v,),status=12);self.assertEqual(self.api(ctx,'VirtualFree',(v,0,0x8000)),1)
    def test_multiplication_and_overflow_flags_against_python_integers(self):
        rng=random.Random(505)
        for n,prefix,opcode in ((1,b'',b'\xf6'),(2,b'\x66',b'\xf7'),(4,b'',b'\xf7'),(8,b'\x48',b'\xf7')):
            bits=n*8;mask=(1<<bits)-1;sign=1<<(bits-1)
            for _ in range(50):
                a=rng.getrandbits(bits);b=rng.getrandbits(bits)
                for signed,modrm in ((False,0xe1),(True,0xe9)):
                    sa=a-(1<<bits) if signed and a&sign else a;sb=b-(1<<bits) if signed and b&sign else b;full=(sa*sb)&((1<<(bits*2))-1)
                    m,_=self.cpu(prefix+opcode+bytes([modrm])+b'\xc3',{0:a,1:b})
                    lo=m.r[0]&mask;hi=(m.r[0]>>8)&255 if n==1 else m.r[2]&mask
                    self.assertEqual((lo,hi),(full&mask,(full>>bits)&mask));self.assertEqual(m.status,0)
                    expected=((full>>bits)&mask)!=(mask if signed and full&sign else 0)
                    self.assertEqual(bool(m.flags&1),expected);self.assertEqual(bool(m.flags&2048),expected)
    def test_unsigned_and_signed_division_quotients_remainders(self):
        rng=random.Random(506)
        for n,prefix,opcode in ((1,b'',b'\xf6'),(2,b'\x66',b'\xf7'),(4,b'',b'\xf7'),(8,b'\x48',b'\xf7')):
            bits=n*8;mask=(1<<bits)-1;limit=1<<(bits-1)
            for _ in range(60):
                divisor=rng.randrange(1,mask+1);hi=rng.randrange(divisor);lo=rng.getrandbits(bits);num=(hi<<bits)|lo
                regs={0:(hi<<8)|lo if n==1 else lo,2:hi,1:divisor};m,_=self.cpu(prefix+opcode+b'\xf1\xc3',regs)
                self.assertEqual(m.status,0);self.assertEqual((m.r[0]&mask,(m.r[0]>>8)&255 if n==1 else m.r[2]&mask),divmod(num,divisor))
                signed_divisor=rng.randrange(-limit,limit) or 1;signed_num=rng.randrange(-limit,limit)
                q=abs(signed_num)//abs(signed_divisor);q=-q if (signed_num<0)!=(signed_divisor<0) else q;r=signed_num-q*signed_divisor
                full=signed_num&((1<<(2*bits))-1);hi=full>>bits;lo=full&mask
                m,_=self.cpu(prefix+opcode+b'\xf9\xc3',{0:full if n==1 else lo,2:hi,1:signed_divisor&mask})
                if q>=limit:self.assertEqual(m.status,11)
                else:self.assertEqual(m.status,0);self.assertEqual((m.r[0]&mask,(m.r[0]>>8)&255 if n==1 else m.r[2]&mask),(q&mask,r&mask))
    def test_division_faults_leave_dividend_registers_intact(self):
        for code,regs in [('48f7f1c3',{0:12,2:0,1:0}),('48f7f1c3',{0:1,2:5,1:5}),('48f7f9c3',{0:1<<63,2:MASK,1:MASK})]:
            m,_=self.cpu(code,regs);self.assertEqual(m.status,11);self.assertFalse(m.exited);self.assertEqual(m.r[0],regs[0]);self.assertEqual(m.r[2],regs[2]);self.assertEqual(m.last_guest_ip,PREFERRED+0x1000)
    def test_shifts_rotates_sign_extension_and_imul_forms(self):
        for group,kind in ((4,'left'),(5,'right'),(7,'arithmetic'),(0,'rol'),(1,'ror')):
            for count in (0,1,7,31,32,63,64,255):
                value=0x8123456789abcdef;c=count&63
                if kind=='left':expected=(value<<c)&MASK
                elif kind=='right':expected=value>>c
                elif kind=='arithmetic':expected=((value-(1<<64))>>c)&MASK
                elif kind=='rol':expected=((value<<c)|(value>>(64-c if c else 64)))&MASK
                else:expected=((value>>c)|(value<<(64-c if c else 64)))&MASK
                m,_=self.cpu(bytes([0x48,0xc1,0xc0|(group<<3),count,0xc3]),{0:value});self.assertEqual(m.r[0],expected,(kind,count));self.assertEqual(m.status,0)
        for code,regs,expected in [('4863c1c3',{1:0x80000000},0xffffffff80000000),('4898c3',{0:0x80000000},0xffffffff80000000),('480fbec1c3',{1:0x80},0xffffffffffffff80),('486bc1fdc3',{1:7},(-21)&MASK),('4869c1fdffffffc3',{1:7},(-21)&MASK),('480fafc1c3',{0:7,1:-3},(-21)&MASK)]:
            m,_=self.cpu(code,regs);self.assertEqual(m.r[0],expected);self.assertEqual(m.status,0)
    def test_negative_runtime_receipts_have_fault_location_and_no_success(self):
        for name,code,status in [('divide',bytes.fromhex('31c9 31d2 b801000000 f7f1'),11),('access',bytes.fromhex('31c0 8b00'),6),('opcode',b'\x0f\x0b',7)]:
            image=self.directory/(name+'.exe');image.write_bytes(pe(code));r=execute(self.w5probe,image)
            self.assertEqual(r['status'],status);self.assertFalse(r['exited']);self.assertTrue(r['guest_ip']);self.assertNotEqual(r['stop'],'ok');self.assertEqual(r['stdout_hex'],'')
    def test_suite_provenance_cannot_be_claimed_from_a_fake_receipt(self):
        receipt=self.directory/'suite.json';receipt.write_text(json.dumps({'schema':'compact-windows-w5-reference/v1','native_reference_passed':True,'source_commit':'wrong'}))
        with patch.dict(os.environ,{'GITHUB_SHA':'a'*40}):
            with self.assertRaises(ValueError):compare(self.w5probe,self.directory,receipt,self.directory/'out.json')

if __name__=='__main__':unittest.main()
