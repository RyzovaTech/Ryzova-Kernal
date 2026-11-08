# SPDX-License-Identifier: GPL-3.0-only
"""Real object state, transactional waits, bounded handles and recursive locks."""
import ctypes as C
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
import test_compact_windows_w2 as w2
from test_compact_windows_w3 import Services,Launch,launch
from compact_windows_w5 import ALL_APIS
from compact_windows_w7_startup import APIS as STARTUP_APIS
from compact_windows_w7_sync import sync_fixture,SYNC_APIS,LOW_MASK,HIGH_MASK,EXPECTED_CALLS
CATALOG=(*ALL_APIS,*STARTUP_APIS[:7],*SYNC_APIS)
PROCESS=0xffffffffffffffff
THREAD=PROCESS-1


class WindowsW7SyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w2.WindowsW2Tests.setUpClass.__func__(cls)
        cls.lib.cw_attach_services.argtypes=[C.POINTER(w2.Machine),C.POINTER(Services),C.POINTER(Launch),C.c_void_p,C.c_size_t]
        cls.lib.cw_api_dispatch.argtypes=[C.POINTER(w2.Machine)]
    tearDownClass=classmethod(w2.WindowsW2Tests.tearDownClass.__func__)
    admitted=w2.WindowsW2Tests.admitted
    loaded=w2.WindowsW2Tests.loaded

    def context(self,image=None,high=HIGH_MASK):
        m,arena=self.loaded(image or sync_fixture());s=Services();policy=launch();policy.api_mask=LOW_MASK;policy.api_mask_high[0]=high
        heap=C.create_string_buffer(4096)
        status=self.lib.cw_attach_services(C.byref(m),C.byref(s),C.byref(policy),heap,len(heap))
        return status,m,s,arena,heap
    def dispatch(self,ctx,name,args=()):
        _,m,s,arena,heap=ctx;m.r[4]=m.initial_sp-128;m.ip=0xffffffffff000000+16*CATALOG.index(name)
        values=(*args,0,0,0,0,0,0,0)
        for reg,value in zip((1,2,8,9),values):m.r[reg]=value
        self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4],struct.pack('<Q',m.plan.base+m.plan.entry),8),0)
        self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4]+40,struct.pack('<QQQ',*values[4:7]),24),0)
        return self.lib.cw_api_dispatch(C.byref(m))
    def api(self,ctx,name,*args):
        self.assertEqual(self.dispatch(ctx,name,args),0,name);return ctx[1].r[0]
    def event(self,ctx,manual=0,initial=0):return self.api(ctx,'CreateEventA',0,manual,initial,0)
    def read(self,ctx,at,n):
        out=C.create_string_buffer(n);self.assertEqual(self.lib.cw_read(C.byref(ctx[1]),at,out,n,1),0);return out.raw
    def write(self,ctx,at,data):self.assertEqual(self.lib.cw_write(C.byref(ctx[1]),at,data,len(data)),0)
    def duplicate(self,ctx,source,access=0,options=2,target=PROCESS,out=None):
        out=out or ctx[1].plan.base+0x2c18
        result=self.api(ctx,'DuplicateHandle',PROCESS,source,target,out,access,0,options)
        return result,struct.unpack('<Q',self.read(ctx,out,8))[0]

    def test_full_program_executes_and_releases_all_objects(self):
        ctx=self.context();_,m,s,arena,heap=ctx;self.assertEqual(ctx[0],0)
        saved={}
        for reg in (3,5,6,7,12,13,14,15):m.r[reg]=saved[reg]=0x1357246800000000+reg
        self.assertEqual(self.lib.cw_run(C.byref(m),1000),0)
        self.assertEqual((m.exited,m.exit_code),(1,43))
        self.assertEqual({name:s.calls[i] for i,name in enumerate(CATALOG) if s.calls[i]},EXPECTED_CALLS)
        self.assertFalse(any(h.token for h in s.sync_handles));self.assertFalse(any(o.refs for o in s.sync_objects))
        self.assertFalse(any(c.address for c in s.criticals));self.assertEqual({r:m.r[r] for r in saved},saved)

    def test_sync_apis_require_their_own_explicit_high_word_grants(self):
        for high in (0,7,HIGH_MASK ^ (1<<(35-32)),HIGH_MASK ^ (1<<(51-32))):
            ctx=self.context(high=high);self.assertEqual(ctx[0],10)
            self.assertFalse(ctx[1].services);self.assertEqual(ctx[1].instructions,0)

    def test_manual_and_auto_reset_events_are_different(self):
        ctx=self.context();auto=self.event(ctx);manual=self.event(ctx,1,1)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',auto,0),258)
        self.api(ctx,'SetEvent',auto);self.api(ctx,'SetEvent',auto)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',auto,0xffffffff),0)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',auto,0),258)
        for _ in range(3):self.assertEqual(self.api(ctx,'WaitForSingleObject',manual,0),0)
        self.api(ctx,'ResetEvent',manual);self.assertEqual(self.api(ctx,'WaitForSingleObject',manual,0),258)

    def test_handle_numbers_are_local_and_stale_generations_are_invalid(self):
        first=self.context();other=self.context();a=self.event(first,0,1);b=self.event(other)
        self.assertEqual(a,b) # Same numbers resolve to each environment's own object.
        self.assertEqual(self.api(first,'WaitForSingleObject',a,0),0)
        self.assertEqual(self.api(other,'WaitForSingleObject',a,0),258)
        self.api(first,'CloseHandle',a);new=self.event(first)
        self.assertNotEqual(new,a);self.assertEqual(self.api(first,'SetEvent',a),0);self.assertEqual(first[2].last_error,6)
        self.assertEqual(self.api(first,'SetEvent',new),1)

    def test_semaphore_overflow_and_invalid_output_do_not_mutate_state(self):
        ctx=self.context();sem=self.api(ctx,'CreateSemaphoreA',0,1,2,0);out=ctx[1].plan.base+0x2c68
        self.write(ctx,out,b'abcd')
        self.assertEqual(self.api(ctx,'ReleaseSemaphore',sem,2,out),0);self.assertEqual(ctx[2].last_error,298)
        self.assertEqual(self.read(ctx,out,4),b'abcd')
        self.assertEqual(self.api(ctx,'ReleaseSemaphore',sem,1,ctx[1].plan.base+0x1000),0);self.assertEqual(ctx[2].last_error,998)
        self.assertEqual(self.api(ctx,'ReleaseSemaphore',sem,1,out),1);self.assertEqual(self.read(ctx,out,4),struct.pack('<I',1))
        self.assertEqual(self.api(ctx,'WaitForSingleObject',sem,0),0)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',sem,0),0)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',sem,0),258)
        for initial,maximum in ((-1,2),(3,2),(0,0)):
            self.assertEqual(self.api(ctx,'CreateSemaphoreA',0,initial&0xffffffff,maximum,0),0)
            self.assertEqual(ctx[2].last_error,87)

    def test_wait_all_is_atomic_and_wait_any_chooses_lowest_ready_index(self):
        ctx=self.context();event=self.event(ctx);sem=self.api(ctx,'CreateSemaphoreA',0,1,2,0);at=ctx[1].plan.base+0x2c20
        self.write(ctx,at,struct.pack('<QQ',sem,event))
        self.assertEqual(self.api(ctx,'WaitForMultipleObjects',2,at,1,0),258)
        self.api(ctx,'SetEvent',event)
        self.assertEqual(self.api(ctx,'WaitForMultipleObjects',2,at,1,0),0)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',sem,0),258)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',event,0),258)
        self.api(ctx,'ReleaseSemaphore',sem,1,0);self.api(ctx,'SetEvent',event)
        self.assertEqual(self.api(ctx,'WaitForMultipleObjects',2,at,0,0),0)
        self.assertEqual(self.api(ctx,'WaitForMultipleObjects',2,at,0,0),1)

    def test_wait_validation_does_not_consume_signals(self):
        ctx=self.context();h=self.event(ctx,0,1);at=ctx[1].plan.base+0x2c20
        for tokens in ((h,0x12345678),(h,h)):
            self.write(ctx,at,struct.pack('<QQ',*tokens))
            self.assertEqual(self.api(ctx,'WaitForMultipleObjects',2,at,1,0),0xffffffff)
        self.assertEqual(self.api(ctx,'WaitForMultipleObjects',17,at,0,0),0xffffffff);self.assertEqual(ctx[2].last_error,87)
        self.assertEqual(self.api(ctx,'WaitForMultipleObjects',2,0xffffffffffffffff,0,0),0xffffffff);self.assertEqual(ctx[2].last_error,998)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',h,0),0)

    def test_unsupported_blocking_wait_halts_without_a_fake_completion(self):
        ctx=self.context(sync_fixture(blocking=True));m=ctx[1]
        self.assertEqual(self.lib.cw_run(C.byref(m),1000),10)
        self.assertFalse(m.exited);self.assertNotEqual(m.exit_code,43)
        self.assertEqual(ctx[2].calls[CATALOG.index('WaitForSingleObject')],1)

    def test_duplicate_lifetime_rights_and_close_source_failure_semantics(self):
        ctx=self.context();original=self.event(ctx,0,1);ok,dup=self.duplicate(ctx,original)
        self.assertEqual(ok,1);self.api(ctx,'CloseHandle',original)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',dup,0),0)
        ok,reduced=self.duplicate(ctx,dup,access=2,options=0);self.assertEqual(ok,1)
        self.assertEqual(self.api(ctx,'SetEvent',reduced),1)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',reduced,0),0xffffffff);self.assertEqual(ctx[2].last_error,5)
        ok,_=self.duplicate(ctx,reduced,access=0x100000,options=1)
        self.assertEqual(ok,0);self.assertEqual(ctx[2].last_error,5)
        self.assertEqual(self.api(ctx,'SetEvent',reduced),0);self.assertEqual(ctx[2].last_error,6)
        ok,new=self.duplicate(ctx,dup,options=3);self.assertEqual(ok,1)
        self.assertEqual(self.api(ctx,'SetEvent',dup),0)
        self.assertEqual(self.api(ctx,'WaitForSingleObject',new,0),0)
        self.assertEqual(self.duplicate(ctx,new,options=3,target=0x12345678)[0],0)
        self.assertEqual(self.api(ctx,'SetEvent',new),0)

    def test_pseudo_identities_are_virtual_and_duplicate_to_real_private_handles(self):
        ctx=self.context();self.assertEqual(self.api(ctx,'GetCurrentProcess'),PROCESS)
        self.assertEqual(self.api(ctx,'GetCurrentThread'),THREAD)
        self.assertEqual(self.api(ctx,'GetCurrentProcessId'),1);self.assertEqual(self.api(ctx,'GetCurrentThreadId'),1)
        for pseudo in (PROCESS,THREAD):
            ok,h=self.duplicate(ctx,pseudo);self.assertEqual(ok,1);self.assertNotEqual(h,pseudo)
            self.assertEqual(self.api(ctx,'WaitForSingleObject',h,0),258);self.api(ctx,'CloseHandle',h)

    def test_object_handle_and_generation_limits_are_bounded(self):
        ctx=self.context();handles=[self.event(ctx) for _ in range(32)]
        self.assertTrue(all(handles));self.assertEqual(self.event(ctx),0);self.assertEqual(ctx[2].last_error,8)
        for h in handles:self.api(ctx,'CloseHandle',h)
        source=self.event(ctx);copies=[self.duplicate(ctx,source)[1] for _ in range(63)]
        self.assertEqual(len(set([source,*copies])),64)
        self.assertEqual(self.duplicate(ctx,source)[0],0);self.assertEqual(ctx[2].last_error,8)
        for h in [source,*copies]:self.api(ctx,'CloseHandle',h)
        self.assertFalse(any(o.refs for o in ctx[2].sync_objects))
        ctx[2].sync_serial=0xffffffff
        self.assertEqual(self.event(ctx),0);self.assertFalse(any(o.refs for o in ctx[2].sync_objects))

    def test_critical_section_recursion_mirror_and_invalid_lifecycle(self):
        ctx=self.context();at=ctx[1].plan.base+0x2c40
        self.api(ctx,'InitializeCriticalSection',at)
        self.api(ctx,'EnterCriticalSection',at);self.api(ctx,'EnterCriticalSection',at)
        self.assertEqual(self.api(ctx,'TryEnterCriticalSection',at),1)
        self.assertEqual(struct.unpack('<I',self.read(ctx,at+12,4))[0],3)
        self.assertEqual(struct.unpack('<Q',self.read(ctx,at+16,8))[0],1)
        self.assertEqual(self.dispatch(ctx,'DeleteCriticalSection',(at,)),10)
        for _ in range(3):self.api(ctx,'LeaveCriticalSection',at)
        self.assertEqual(self.dispatch(ctx,'LeaveCriticalSection',(at,)),10)
        self.api(ctx,'DeleteCriticalSection',at)
        self.assertEqual(self.dispatch(ctx,'EnterCriticalSection',(at,)),10)
        self.assertEqual(self.dispatch(ctx,'InitializeCriticalSection',(ctx[1].plan.base+0x1000,)),6)

    def test_critical_table_capacity_and_environment_isolation(self):
        first=self.context();other=self.context();at=first[1].stack_base+0x100
        for i in range(32):self.api(first,'InitializeCriticalSection',at+i*40)
        self.assertEqual(self.dispatch(first,'InitializeCriticalSection',(at+32*40,)),10)
        self.api(first,'EnterCriticalSection',at)
        self.api(other,'InitializeCriticalSection',at);self.api(other,'TryEnterCriticalSection',at)
        self.assertEqual(first[2].criticals[0].depth,1);self.assertEqual(other[2].criticals[0].depth,1)

    def test_bad_duplicate_output_and_short_argument_frame_do_not_leak_handles(self):
        ctx=self.context();source=self.event(ctx);count=lambda:sum(bool(h.token) for h in ctx[2].sync_handles)
        before=count()
        self.assertEqual(self.api(ctx,'DuplicateHandle',PROCESS,source,PROCESS,ctx[1].plan.base+0x1000,0,0,2),0)
        self.assertEqual(count(),before)
        m=ctx[1];m.r[4]=m.stack_base+65536-40;m.ip=0xffffffffff000000+51*16
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),9);self.assertEqual(count(),before)

    def test_unimplemented_names_and_security_descriptors_do_not_create_objects(self):
        ctx=self.context()
        self.assertEqual(self.api(ctx,'CreateEventA',1,0,0,0),0)
        self.assertEqual(self.api(ctx,'CreateEventA',0,0,0,1),0)
        self.assertEqual(ctx[2].last_error,50)
        self.assertFalse(any(o.refs for o in ctx[2].sync_objects))


if __name__=='__main__':unittest.main()
