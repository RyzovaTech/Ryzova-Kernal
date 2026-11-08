# SPDX-License-Identifier: GPL-3.0-only
"""Opt-in tracing is fail-stop; CRT startup executes guest callbacks and arguments."""
import ctypes as C
import struct
import subprocess
import unittest

import test_compact_windows_w2 as w2
from test_compact_windows_w3 import Services, Launch, launch, put_utf16
from compact_windows_w5 import imported_pe_modules


class WindowsW7TraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w2.WindowsW2Tests.setUpClass.__func__(cls)
        cls.lib.cw_plan_profile.argtypes = cls.lib.cw_plan.argtypes + [C.c_uint32]
        cls.lib.cw_load_profile.argtypes = cls.lib.cw_load.argtypes + [C.c_uint32]
        cls.lib.cw_attach_services.argtypes = [C.POINTER(w2.Machine), C.POINTER(Services), C.POINTER(Launch), C.c_void_p, C.c_size_t]
        cls.lib.cw_api_dispatch.argtypes = [C.POINTER(w2.Machine)]
        cls.lib.cw_api_id.argtypes = [C.c_char_p]
        cls.lib.cw_api_word_mask.argtypes = [C.c_uint]
        cls.lib.cw_api_word_mask.restype = C.c_uint32

    tearDownClass = classmethod(w2.WindowsW2Tests.tearDownClass.__func__)

    def context(self, image, profile=0, command='jq.exe', approved=None):
        p = w2.Plan()
        self.assertEqual(self.lib.cw_plan_profile(image, len(image), 0, C.byref(p), profile), 0)
        m = w2.Machine(); arena = C.create_string_buffer(p.image_bytes+65536)
        self.assertEqual(self.lib.cw_load_profile(image, len(image), 0, arena, len(arena), C.byref(m), profile), 0)
        s = Services(); policy = launch(); policy.profile_flags = profile if approved is None else approved
        policy.api_mask = self.lib.cw_api_word_mask(0)
        for i in range(7): policy.api_mask_high[i] = self.lib.cw_api_word_mask(i+1)
        put_utf16(policy.command_line, command)
        heap = C.create_string_buffer(65536)
        status = self.lib.cw_attach_services(C.byref(m), C.byref(s), C.byref(policy), heap, len(heap))
        return m, s, arena, heap, status

    def api(self, ctx, name, *args):
        m = ctx[0]; ident = self.lib.cw_api_id(name.encode()); self.assertGreaterEqual(ident, 0)
        m.ip = 0xffffffffff000000 + ident*16; m.r[4] = m.initial_sp-64
        for reg, value in zip((1,2,8,9), (*args,0,0,0,0)): m.r[reg] = value
        self.assertEqual(self.lib.cw_write(C.byref(m), m.r[4], struct.pack('<Q',m.plan.base+0x1000),8),0)
        if len(args)>4:
            raw=struct.pack('<'+'Q'*(len(args)-4),*args[4:])
            self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4]+40,raw,len(raw)),0)
        return self.lib.cw_api_dispatch(C.byref(m))

    def read(self, m, at, n):
        out=C.create_string_buffer(n)
        self.assertEqual(self.lib.cw_read(C.byref(m),at,out,n,1),0)
        return out.raw

    def test_unknown_import_needs_both_explicit_admission_and_launch(self):
        image=imported_pe_modules(b'\xc3', {'other.dll':['UnknownExport']})
        p=w2.Plan()
        self.assertEqual(self.lib.cw_plan(image,len(image),0,C.byref(p)),2)
        ctx=self.context(image,1,approved=0)
        self.assertEqual(ctx[-1],10); self.assertFalse(ctx[0].services)
        ctx=self.context(image,1)
        self.assertEqual(ctx[-1],0)
        self.assertEqual((ctx[0].plan.import_count,ctx[0].plan.unresolved_imports),(1,1))
        self.assertEqual(self.lib.cw_run(C.byref(ctx[0]),100),0)
        self.assertTrue(ctx[0].exited)
        self.assertFalse(any(ctx[1].calls))

    def test_called_unknown_export_halts_without_success_or_output(self):
        # Jump through the first IAT slot; no pretend implementation.
        image=imported_pe_modules(b'\xff\x25'+struct.pack('<i',0x2280-0x1006), {'other.dll':['UnknownExport']})
        ctx=self.context(image,1);m,s=ctx[:2]
        self.assertEqual(self.lib.cw_run(C.byref(m),100),13)
        self.assertEqual((m.stop_import,m.instructions,m.exited),(1,2,0))
        self.assertFalse(any(s.calls));self.assertEqual(list(s.output_bytes),[0,0])
        # The immutable patched IAT cannot be replaced by guest code.
        self.assertNotEqual(self.lib.cw_write(C.byref(m),m.plan.base+0x2280,bytes(8),8),0)

    def test_wrong_dll_contract_is_not_bound_to_an_implemented_export(self):
        image=imported_pe_modules(b'\xc3',{'other.dll':['ExitProcess']})
        ctx=self.context(image,1);m=ctx[0]
        self.assertEqual(m.plan.api_mask,0);self.assertEqual(m.plan.imports[0].api,0xffffffff)
        m.ip=0xffffffffff000020
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),10)

    def test_unknown_profile_bits_do_not_modify_the_arena(self):
        image=w2.pe(b'\xc3');m=w2.Machine();arena=C.create_string_buffer(b'A'*131072);before=arena.raw
        self.assertEqual(self.lib.cw_load_profile(image,len(image),0,arena,len(arena),C.byref(m),4),2)
        self.assertEqual(arena.raw,before);self.assertFalse(m.image)

    def test_locked_arithmetic_checks_writable_memory_before_changes(self):
        code = b'\xf0\x83\x03\x01\xc3'  # lock add dword [rbx], 1
        ctx = self.context(w2.pe(code, struct.pack('<I', 9)))
        m = ctx[0]
        m.r[3] = m.plan.base + 0x2000
        self.assertEqual(self.lib.cw_run(C.byref(m), 10), 0)
        self.assertEqual(self.read(m, m.r[3], 4), struct.pack('<I', 10))
        ctx = self.context(w2.pe(code))
        m = ctx[0]
        m.r[3] = m.plan.base + 0x1000
        flags = m.flags
        self.assertEqual(self.lib.cw_run(C.byref(m), 10), 6)
        self.assertEqual(m.flags, flags)
        ctx = self.context(w2.pe(b'\xf0\x83\xc0\x01\xc3'))
        self.assertEqual(self.lib.cw_run(C.byref(ctx[0]), 10), 7)

    def test_rep_store_is_charged_per_element(self):
        ctx = self.context(w2.pe(b'\xf3\x48\xab\xc3', bytes(32)))
        m = ctx[0]
        target = m.plan.base + 0x2000
        m.r[0], m.r[1], m.r[7] = 42, 4, target
        self.assertEqual(self.lib.cw_run(C.byref(m), 2), 8)
        self.assertEqual(self.read(m, target, 32), struct.pack('<QQQQ', 42, 42, 0, 0))
        self.assertEqual((m.r[1], m.r[7]), (2, target+16))

    def test_trace_crt_heap_checks_live_blocks_and_zeroes_reused_ranges(self):
        names = {'ucrtbase.dll': ['malloc', 'calloc', 'free', 'realloc']}
        ctx = self.context(imported_pe_modules(b'\xc3', names), profile=3)
        m = ctx[0]
        addresses = []
        for _ in range(24):
            self.assertEqual(self.api(ctx, 'malloc', 16), 0)
            self.assertNotEqual(m.r[0], 0)
            addresses.append(m.r[0])
        first, second = addresses[:2]
        self.assertEqual(second, first+16)
        out = C.create_string_buffer(32)
        self.assertNotEqual(self.lib.cw_read(C.byref(m), first, out, 32, 1), 0)
        self.assertEqual(self.lib.cw_write(C.byref(m), first, b'private', 7), 0)
        self.assertEqual(self.api(ctx, 'realloc', first, 64), 0)
        self.assertEqual(self.read(m, m.r[0], 7), b'private')
        self.assertNotEqual(self.lib.cw_read(C.byref(m), first, out, 1, 1), 0)
        self.assertEqual(self.api(ctx, 'calloc', 2, 8), 0)
        self.assertEqual(m.r[0], first)
        self.assertEqual(self.read(m, first, 16), bytes(16))

    def test_handler_metadata_is_opaque_and_requires_read_only_backing(self):
        data = bytearray(64)
        struct.pack_into('<III', data, 0, 0x1000, 0x1001, 0x2010)
        data[16:24] = b'\x09\0\0\0' + struct.pack('<I', 0x1000)
        image = bytearray(w2.pe(b'\xc3', bytes(data)))
        permissions = 0x188 + 40 + 36
        struct.pack_into('<I', image, permissions, 0x40000040)
        struct.pack_into('<II', image, 0x98 + 112 + 3*8, 0x2000, 12)
        plan = w2.Plan()

        def admit(blob, flags):
            return self.lib.cw_plan_profile(bytes(blob), len(blob), 0, C.byref(plan), flags)

        self.assertNotEqual(admit(image, 0), 0)
        self.assertEqual(admit(image, 2), 0)
        for offset, fmt, value in (
            (permissions, '<I', 0xc0000040),  # Writable metadata.
            (0x400 + 20, '<I', 0x2000),       # Handler points to non-executable data.
            (0x400 + 16, '<B', 0x21),        # Chained unwind info is unsupported.
            (0x400 + 18, '<B', 255),         # Claimed slots exceed the backing.
        ):
            with self.subTest(offset=offset, value=value):
                bad = bytearray(image)
                struct.pack_into(fmt, bad, offset, value)
                self.assertNotEqual(admit(bad, 2), 0)

    def test_registrars_and_crt_modes_are_stateful_and_isolated(self):
        image=imported_pe_modules(b'\xc3',{'kernel32.dll':['SetUnhandledExceptionFilter'],
            'ucrtbase.dll':['_set_invalid_parameter_handler','_set_app_type','__p__fmode','__p__commode','_set_new_mode']})
        ctx=self.context(image);other=self.context(image);m,s=ctx[:2];callback=m.plan.base+0x1000
        for name,field in [('SetUnhandledExceptionFilter','exception_filter'),('_set_invalid_parameter_handler','invalid_parameter_handler')]:
            self.assertEqual(self.api(ctx,name,callback),0);self.assertEqual(m.r[0],0)
            self.assertEqual(getattr(s,field),callback);self.assertEqual(getattr(other[1],field),0)
            self.assertEqual(self.api(ctx,name,0),0);self.assertEqual(m.r[0],callback)
            self.assertNotEqual(self.api(ctx,name,m.plan.base+0x2000),0)
        self.assertEqual(self.api(ctx,'_set_app_type',1),0);self.assertEqual(s.crt_app_type,1)
        self.assertEqual(self.api(ctx,'_set_new_mode',1),0);self.assertEqual(m.r[0],0)
        self.assertEqual(self.api(ctx,'_set_new_mode',0),0);self.assertEqual(m.r[0],1)
        self.assertEqual(self.api(ctx,'__p__fmode'),0);at=m.r[0]
        self.assertEqual(self.read(m,at,4),struct.pack('<I',0x4000))
        self.assertEqual(self.lib.cw_write(C.byref(m),at,struct.pack('<I',0x8000),4),0)
        self.assertEqual(self.api(ctx,'__p__fmode'),0);self.assertEqual(self.read(m,m.r[0],4),struct.pack('<I',0x8000))

    def test_wide_arguments_preserve_quotes_backslashes_and_unicode(self):
        names=['_configure_wide_argv','__p___argc','__p___wargv']
        image=imported_pe_modules(b'\xc3',{'ucrtbase.dll':names})
        for args in [['jq.exe','-c','{sum: (.items | add)}','input.json'],
                     ['C:\\Program Files\\jq.exe','','a"b','c\\\\','සිංහල','x\\"z']]:
            ctx=self.context(image,command=subprocess.list2cmdline(args));m=ctx[0]
            self.assertEqual(self.api(ctx,'_configure_wide_argv',1),0)
            self.assertEqual(self.api(ctx,'__p___argc'),0)
            self.assertEqual(struct.unpack('<I',self.read(m,m.r[0],4))[0],len(args))
            self.assertEqual(self.api(ctx,'__p___wargv'),0)
            vector=struct.unpack('<Q',self.read(m,m.r[0],8))[0];actual=[]
            for i in range(len(args)):
                at=struct.unpack('<Q',self.read(m,vector+i*8,8))[0];raw=bytearray()
                for j in range(1024):
                    ch=self.read(m,at+j*2,2)
                    if ch==b'\0\0':break
                    raw.extend(ch)
                actual.append(raw.decode('utf-16le'))
            self.assertEqual(actual,args)
            self.assertEqual(self.read(m,vector+len(args)*8,8),bytes(8))
        self.assertEqual(self.api(ctx,'_configure_wide_argv',2),12)

    def test_initializers_execute_guest_callbacks_and_stop_on_error(self):
        # Callback writes a marker through RIP-relative addressing and returns 7.
        code=b'\x48\x83\xc4\x38\xc3'+b'\x90'*11+b'\xc7\x05'+struct.pack('<i',0x2c20-0x101a)+struct.pack('<I',0x12345678)+b'\xb8\x07\0\0\0\xc3'
        image=imported_pe_modules(code,{'ucrtbase.dll':['_initterm','_initterm_e']},bytes(64))
        for checked in (False,True):
            ctx=self.context(bytes(image));m,s=ctx[:2];table=m.plan.base+0x2c00
            self.assertEqual(self.lib.cw_write(C.byref(m),table,struct.pack('<QQ',m.plan.base+0x1010,0),16),0)
            self.assertEqual(self.api(ctx,'_initterm_e' if checked else '_initterm',table,table+16),0)
            self.assertEqual(s.crt_init_depth,1)
            # Return address points to the fixture's RET; run through trusted continuation.
            self.assertEqual(self.lib.cw_run(C.byref(m),100),0)
            self.assertTrue(m.exited);self.assertEqual(s.crt_init_depth,0)
            self.assertEqual(self.read(m,table+32,4),struct.pack('<I',0x12345678))
            self.assertEqual(m.exit_code,7 if checked else 0)

    def test_exit_callbacks_execute_lifo_and_quick_exit_skips_them(self):
        # Each callback appends a digit to a writable marker.
        callbacks=[]
        for at,digit in ((0x1010,1),(0x1030,2)):
            load=b'\x8b\x05'+struct.pack('<i',0x2c00-(at+6))
            body=load+b'\x6b\xc0\x0a'+b'\x83\xc0'+bytes([digit])
            body+=b'\x89\x05'+struct.pack('<i',0x2c00-(at+len(body)+6))+b'\xc3'
            callbacks.append(body)
        code=b'\x48\x83\xc4\x38\xc3'+b'\x90'*11+callbacks[0]
        code+=b'\x90'*(0x30-len(code))+callbacks[1]
        image=imported_pe_modules(code,{'ucrtbase.dll':['_crt_atexit','_cexit','exit','_exit']},bytes(64))
        for method,expected,exited in [('_cexit',21,False),('exit',21,True),('_exit',0,True)]:
            ctx=self.context(image);m,s=ctx[:2]
            for at in (0x1010,0x1030): self.assertEqual(self.api(ctx,'_crt_atexit',m.plan.base+at),0)
            self.assertEqual(self.api(ctx,method,37),0)
            if method!='_exit':self.assertEqual(self.lib.cw_run(C.byref(m),100),0)
            self.assertEqual(self.read(m,m.plan.base+0x2c00,4),struct.pack('<I',expected))
            if exited:self.assertEqual((m.exited,m.exit_code),(1,37))
            else:self.assertEqual(s.crt_exit_count,0)

    def test_dynamic_exports_require_module_contract_and_explicit_grant(self):
        image=imported_pe_modules(b'\xc3',{'kernel32.dll':['GetModuleHandleA','GetProcAddress']},bytes(128))
        ctx=self.context(image);m,s=ctx[:2];at=m.plan.base+0x2c00
        raw=b'KERNEL32.dll\0GetLastError\0malloc\0NoSuchExport\0'
        self.assertEqual(self.lib.cw_write(C.byref(m),at,raw,len(raw)),0)
        self.assertEqual(self.api(ctx,'GetModuleHandleA',at),0);handle=m.r[0]
        self.assertNotEqual(handle,0)
        # Merely possessing the exported token does not bind the function.
        m.ip=0xffffffffff000030
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)),10)
        s.last_error=1234
        self.assertEqual(self.api(ctx,'GetProcAddress',handle,at+13),0)
        self.assertEqual(m.r[0],0xffffffffff000030)
        self.assertEqual(self.api(ctx,'GetLastError'),0);self.assertEqual(m.r[0],1234)
        self.assertEqual(self.api(ctx,'GetProcAddress',handle,at+26),0);self.assertEqual(m.r[0],0)
        self.assertEqual(s.last_error,127)
        other=self.context(image);other[1].launch.api_mask &= ~(1<<3)
        self.assertEqual(self.lib.cw_write(C.byref(other[0]),at,raw,len(raw)),0)
        self.assertEqual(self.api(other,'GetProcAddress',handle,at+13),0)
        self.assertEqual(other[0].r[0],0);self.assertEqual(other[1].last_error,5)
        self.assertFalse(any(other[1].dynamic_apis))

    def test_utf8_conversion_sizes_and_writes_unicode_without_partial_failure(self):
        image=imported_pe_modules(b'\xc3',{'kernel32.dll':['WideCharToMultiByte']},bytes(256))
        ctx=self.context(image);m,s=ctx[:2];at=m.plan.base+0x2c00;out=at+128
        text='සිංහල 😀';raw=(text+'\0').encode('utf-16le');encoded=(text+'\0').encode()
        self.assertEqual(self.lib.cw_write(C.byref(m),at,raw,len(raw)),0)
        self.assertEqual(self.api(ctx,'WideCharToMultiByte',65001,0x80,at,0xffffffff,0,0,0,0),0)
        self.assertEqual(m.r[0],len(encoded))
        self.assertEqual(self.api(ctx,'WideCharToMultiByte',65001,0x80,at,0xffffffff,out,len(encoded),0,0),0)
        self.assertEqual(m.r[0],len(encoded));self.assertEqual(self.read(m,out,len(encoded)),encoded)
        before=self.read(m,out,64)
        self.assertEqual(self.api(ctx,'WideCharToMultiByte',65001,0x80,at,0xffffffff,out,1,0,0),0)
        self.assertEqual((m.r[0],s.last_error),(0,122));self.assertEqual(self.read(m,out,64),before)
        self.assertEqual(self.lib.cw_write(C.byref(m),at,b'\0\xd8',2),0)
        self.assertEqual(self.api(ctx,'WideCharToMultiByte',65001,0x80,at,1,out,64,0,0),0)
        self.assertEqual((m.r[0],s.last_error),(0,1113));self.assertEqual(self.read(m,out,64),before)
        self.assertEqual(self.api(ctx,'WideCharToMultiByte',65001,0,at,1,out,64,0,0),0)
        self.assertEqual(self.read(m,out,3),'�'.encode())

    def test_random_requires_provider_and_propagates_real_failure(self):
        image=imported_pe_modules(b'\xc3',{'ucrtbase.dll':['rand_s']},bytes(64))
        ctx=self.context(image);m,s=ctx[:2];at=m.plan.base+0x2c00
        self.assertEqual(self.api(ctx,'rand_s',at),10)
        callback=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_size_t)
        @callback
        def source(_,out,n):
            self.assertEqual(n,4);C.memmove(out,b'\x12\x34\x56\x78',4);return 1
        s.random_read=C.cast(source,C.c_void_p).value
        self.assertEqual(self.api(ctx,'rand_s',at),0)
        self.assertEqual(self.read(m,at,4),b'\x12\x34\x56\x78');self.assertEqual(m.r[0],0)
        @callback
        def unavailable(_,out,n):return 0
        s.random_read=C.cast(unavailable,C.c_void_p).value
        self.assertEqual(self.api(ctx,'rand_s',at),0)
        self.assertEqual(m.r[0],22);self.assertEqual(self.read(m,at,4),bytes(4))


if __name__=='__main__': unittest.main()
