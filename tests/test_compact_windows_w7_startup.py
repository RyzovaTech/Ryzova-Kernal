# SPDX-License-Identifier: AGPL-3.0-only
"""Extended grants, stateful startup APIs and per-environment dynamic TLS."""
import ctypes as C
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'tests')]
import test_compact_windows_w2 as w2
from test_compact_windows_w3 import Services, Launch, launch
from compact_windows_w4 import ALL_APIS as WIN_APIS
from compact_windows_w5 import CRT_APIS, ALL_APIS, imported_pe_modules
from compact_windows_w7_startup import startup_fixture, APIS, LOW_MASK, HIGH_MASK, EXPECTED_CALLS

NEW_APIS = ('AreFileApisANSI', 'SetFileApisToANSI', 'SetFileApisToOEM', 'TlsAlloc',
            'TlsFree', 'TlsGetValue', 'TlsSetValue')
CATALOG = (*ALL_APIS, *NEW_APIS)


class WindowsW7StartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w2.WindowsW2Tests.setUpClass.__func__(cls)
        cls.lib.cw_attach_services.argtypes = [C.POINTER(w2.Machine), C.POINTER(Services), C.POINTER(Launch), C.c_void_p, C.c_size_t]
        cls.lib.cw_api_dispatch.argtypes = [C.POINTER(w2.Machine)]
        cls.lib.cw_api_word_mask.argtypes = [C.c_uint]
        cls.lib.cw_api_word_mask.restype = C.c_uint32

    tearDownClass = classmethod(w2.WindowsW2Tests.tearDownClass.__func__)
    admitted = w2.WindowsW2Tests.admitted
    loaded = w2.WindowsW2Tests.loaded
    denied = w2.WindowsW2Tests.denied

    def context(self, low=LOW_MASK, high=HIGH_MASK):
        m, arena = self.loaded(startup_fixture())
        services = Services();policy = launch();policy.api_mask = low;policy.api_mask_high[0] = high
        heap = C.create_string_buffer(4096)
        status = self.lib.cw_attach_services(C.byref(m), C.byref(services), C.byref(policy), heap, len(heap))
        return status, m, services, arena, heap

    def api(self, ctx, name, *args):
        _, m, services, arena, heap = ctx
        m.r[4] = m.initial_sp-64;m.ip = 0xffffffffff000000+CATALOG.index(name)*16
        for reg, value in zip((1, 2, 8, 9), (*args, 0, 0, 0, 0)):m.r[reg] = value
        self.assertEqual(self.lib.cw_write(C.byref(m), m.r[4], struct.pack('<Q', m.plan.base+m.plan.entry), 8), 0)
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)), 0, name)
        return m.r[0]

    def test_complete_stateful_program_really_executes_across_mask_boundary(self):
        ctx = self.context();_, m, services, arena, heap = ctx
        self.assertEqual(ctx[0], 0)
        self.assertEqual((m.plan.api_mask, m.plan.api_mask_high[0]), (LOW_MASK, HIGH_MASK))
        self.assertEqual(self.lib.cw_run(C.byref(m), 1000), 0)
        self.assertEqual((m.exited, m.exit_code), (1, 41))
        self.assertEqual({name: services.calls[i] for i, name in enumerate(CATALOG) if services.calls[i]}, EXPECTED_CALLS)
        self.assertEqual(list(services.tls_used), [0, 0])
        self.assertEqual(services.file_apis_ansi, 1)

    def test_missing_low_or_high_grants_do_not_attach_or_execute(self):
        for low, high in (((1<<28)-1, 7), (LOW_MASK, 0), (LOW_MASK ^ (1<<31), 7)):
            with self.subTest(low=low, high=high):
                ctx = self.context(low, high)
                self.assertEqual(ctx[0], 10);self.assertFalse(ctx[1].services);self.assertEqual(ctx[1].instructions, 0)
        for bit in (1, 2, 4):self.assertEqual(self.context(LOW_MASK, 7 ^ bit)[0], 10)

    def test_reserved_words_and_bits_are_not_authority(self):
        for word in range(7):
            m, arena = self.loaded(startup_fixture());services = Services();heap = C.create_string_buffer(4096)
            policy = launch();policy.api_mask = LOW_MASK;policy.api_mask_high[0] = 7
            policy.api_mask_high[word] |= 0x80000000
            self.assertEqual(self.lib.cw_attach_services(C.byref(m), C.byref(services), C.byref(policy), heap, len(heap)), 10)
            self.assertFalse(m.services)
        self.assertEqual([self.lib.cw_api_word_mask(i) for i in (0, 1, 2, 7, 8, 0xffffffff)], [0xffffffff, 0xfffff, 0, 0, 0, 0])

    def test_forged_high_thunk_does_not_bypass_declared_imports(self):
        ctx = self.context();_, m, services, arena, heap = ctx
        m.plan.api_mask_high[0] &= ~2
        m.ip = 0xffffffffff000000+33*16
        before = bytes(services)
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)), 10)
        self.assertEqual(bytes(services), before)
        m.ip = 0xffffffffff000000+255*16
        self.assertEqual(self.lib.cw_api_dispatch(C.byref(m)), 6)

    def test_mode_changes_and_tls_values_are_isolated_between_environments(self):
        first = self.context();other = self.context()
        self.assertEqual(self.api(first, 'AreFileApisANSI'), 1)
        self.api(first, 'SetFileApisToOEM')
        self.assertEqual(self.api(first, 'AreFileApisANSI'), 0)
        self.assertEqual(self.api(other, 'AreFileApisANSI'), 1)
        a = self.api(first, 'TlsAlloc');b = self.api(other, 'TlsAlloc')
        self.assertEqual(self.api(first, 'TlsSetValue', a, 0xffffffffffffffff), 1)
        self.assertEqual(self.api(first, 'TlsGetValue', a), 0xffffffffffffffff)
        self.assertEqual(self.api(other, 'TlsGetValue', b), 0)

    def test_allocation_capacity_reuse_and_zero_initialization(self):
        ctx = self.context();slots = [self.api(ctx, 'TlsAlloc') for _ in range(64)]
        self.assertEqual(len(set(slots)), 64)
        self.assertEqual(self.api(ctx, 'TlsAlloc'), 0xffffffff)
        self.assertEqual(ctx[2].last_error, 8)
        self.assertEqual(self.api(ctx, 'TlsSetValue', slots[31], 0x123456789abcdef0), 1)
        self.assertEqual(self.api(ctx, 'TlsFree', slots[31]), 1)
        reused = self.api(ctx, 'TlsAlloc');self.assertEqual(reused, slots[31])
        self.assertEqual(self.api(ctx, 'TlsGetValue', reused), 0)
        self.assertEqual(ctx[2].last_error, 0)

    def test_zero_and_invalid_values_have_distinguishable_last_errors(self):
        ctx = self.context();slot = self.api(ctx, 'TlsAlloc')
        self.api(ctx, 'SetLastError', 777)
        self.assertEqual(self.api(ctx, 'TlsGetValue', slot), 0);self.assertEqual(ctx[2].last_error, 0)
        self.assertEqual(self.api(ctx, 'TlsGetValue', 0xffffffff), 0);self.assertEqual(ctx[2].last_error, 87)
        self.assertEqual(self.api(ctx, 'TlsSetValue', 64, 123), 0);self.assertEqual(ctx[2].last_error, 87)
        self.assertEqual(self.api(ctx, 'TlsFree', slot), 1)
        self.assertEqual(self.api(ctx, 'TlsFree', slot), 0);self.assertEqual(ctx[2].last_error, 87)
        # The fixed base slot range is accessible without consulting the allocator.
        self.assertEqual(self.api(ctx, 'TlsGetValue', slot), 0);self.assertEqual(ctx[2].last_error, 0)

    def test_free_releases_index_without_freeing_pointed_guest_memory(self):
        ctx = self.context();m = ctx[1];slot = self.api(ctx, 'TlsAlloc');at = m.plan.base+0x2c20
        self.assertEqual(self.lib.cw_write(C.byref(m), at, b'kept', 4), 0)
        self.api(ctx, 'TlsSetValue', slot, at);self.api(ctx, 'TlsFree', slot)
        out = C.create_string_buffer(4)
        self.assertEqual(self.lib.cw_read(C.byref(m), at, out, 4, 1), 0);self.assertEqual(out.raw, b'kept')

    def test_planner_binds_more_than_32_distinct_imports_without_truncation(self):
        image = imported_pe_modules(b'\xc3', {'kernel32.dll': (*WIN_APIS, *NEW_APIS), 'ucrtbase.dll': CRT_APIS})
        status, plan = self.admitted(image)
        self.assertEqual((status, plan.import_count, plan.api_mask, plan.api_mask_high[0]), (0, 35, 0xffffffff, 7))
        self.denied(imported_pe_modules(b'\xc3', {'ucrtbase.dll': ('TlsGetValue',)}))


if __name__ == '__main__':unittest.main()
