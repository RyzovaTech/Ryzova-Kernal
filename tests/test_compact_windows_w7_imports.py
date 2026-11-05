# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded import directories and exact UCRT contracts preserve API authority."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'tests')]
import test_compact_windows_w2 as w2
from test_compact_windows_w3 import Services, Launch, launch
from compact_windows_w2 import PREFERRED
from compact_windows_w5 import imported_pe_modules, ALL_APIS
from compact_windows_w7_imports import import_fixture, verify_reference, MODULES, EXPECTED_CALLS


class WindowsW7ImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w2.WindowsW2Tests.setUpClass.__func__(cls)
        cls.lib.cw_attach_services.argtypes = [C.POINTER(w2.Machine), C.POINTER(Services), C.POINTER(Launch), C.c_void_p, C.c_size_t]
        cls.lib.cw_api_module_id.argtypes = [C.c_char_p]
        cls.lib.cw_api_module_matches.argtypes = [C.c_uint, C.c_char_p]

    tearDownClass = classmethod(w2.WindowsW2Tests.tearDownClass.__func__)
    admitted = w2.WindowsW2Tests.admitted
    loaded = w2.WindowsW2Tests.loaded
    denied = w2.WindowsW2Tests.denied
    mutate = w2.WindowsW2Tests.mutate

    def context(self, image, base=PREFERRED, mask=(1<<28)-1):
        m, arena = self.loaded(image, base)
        services = Services();policy = launch();policy.api_mask = mask
        heap = C.create_string_buffer(1024*1024)
        status = self.lib.cw_attach_services(C.byref(m), C.byref(services), C.byref(policy), heap, len(heap))
        return status, m, services, arena, heap

    def test_six_modules_and_fifteen_apis_really_execute_at_three_bases(self):
        for base in (PREFERRED, PREFERRED+0x40000000, PREFERRED-0x40000000):
            with self.subTest(base=base):
                status, m, services, arena, heap = self.context(import_fixture(), base)
                self.assertEqual(status, 0)
                self.assertEqual(m.plan.import_count, 15)
                saved = {}
                for reg in (3, 5, 6, 7, 12, 13, 14, 15):
                    m.r[reg] = saved[reg] = 0x1357246800000000+reg
                self.assertEqual(self.lib.cw_run(C.byref(m), 1000), 0)
                self.assertEqual((m.exited, m.exit_code), (1, 37))
                self.assertEqual({name: services.calls[i] for i, name in enumerate(ALL_APIS) if services.calls[i]}, EXPECTED_CALLS)
                self.assertEqual({reg: m.r[reg] for reg in saved}, saved)

    def test_alias_imports_require_the_same_canonical_api_grants(self):
        image = import_fixture()
        for name in EXPECTED_CALLS:
            with self.subTest(name=name):
                status, m, services, arena, heap = self.context(image, mask=((1<<28)-1) ^ (1<<ALL_APIS.index(name)))
                self.assertEqual(status, 10)
                self.assertFalse(m.services)
                self.assertEqual(m.instructions, 0)

    def test_exact_contracts_reject_cross_module_exports_and_unknown_aliases(self):
        for module, names in MODULES:
            for name in names:
                image = imported_pe_modules(b'\xc3', {module: (name,)})
                self.assertEqual(self.admitted(image)[0], 0, (module, name))
        for module, name in (
            ('api-ms-win-crt-heap-l1-1-0.dll', 'memcpy'),
            ('api-ms-win-crt-string-l1-1-0.dll', 'malloc'),
            ('api-ms-win-crt-private-l1-1-0.dll', 'WriteFile'),
            ('api-ms-win-crt-runtime-l1-1-0.dll', 'strlen'),
            ('api-ms-win-crt-heap-l1-1-1.dll', 'malloc'),
            ('api-ms-win-crt-anything.dll', 'malloc'),
            ('msvcrt.dll', 'malloc'),
        ):
            with self.subTest(module=module, name=name):
                self.denied(imported_pe_modules(b'\xc3', {module: (name,)}))
        self.denied(imported_pe_modules(b'\xc3', {'ucrtbase.dll': ('malloc',),
                                                  'api-ms-win-crt-heap-l1-1-0.dll': ('malloc',)}))

    def data_raw(self, image):
        return struct.unpack_from('<I', image, 0x188+40+20)[0]

    def test_directory_must_contain_a_bounded_complete_terminator(self):
        image = import_fixture();data = self.data_raw(image)
        # Six descriptors require their seventh, all-zero descriptor as well.
        for size in (39, 120, 139, 65537):
            with self.subTest(size=size):self.denied(self.mutate(0x98+112+8+4, 'I', size, image))
        self.denied(self.mutate(0x98+112+8, 'I', 0x2101, image))
        self.denied(self.mutate(data+0x100+6*20, 'I', 0x2200, image))
        malformed = bytearray(image)
        for i in range(17):
            struct.pack_into('<IIIII', malformed, data+0x100+i*20, 0x2200, 0, 0, 0x2400, 0x2280)
        self.denied(bytes(malformed))

    def test_payload_extent_is_independent_of_descriptor_array_length(self):
        image = import_fixture()
        for size in (140, 141, 0xe00, 0xf00):
            with self.subTest(size=size):
                self.assertEqual(self.admitted(self.mutate(0x98+112+8+4, 'I', size, image))[0], 0)
        # The backing section ends at RVA 0x3000.
        self.denied(self.mutate(0x98+112+8+4, 'I', 0xf01, image))

    def test_duplicate_modules_and_descriptor_thunk_aliasing_are_rejected(self):
        image = import_fixture();data = self.data_raw(image)
        first_name = struct.unpack_from('<I', image, data+0x10c)[0]
        self.denied(self.mutate(data+0x10c+20, 'I', first_name, image))
        for offset in (data+0x100, data+0x110):
            with self.subTest(offset=offset):self.denied(self.mutate(offset, 'I', 0x2100, image))

    def test_aggregate_iat_is_read_only_after_binding(self):
        status, m, services, arena, heap = self.context(import_fixture())
        self.assertEqual(status, 0)
        self.assertNotEqual(self.lib.cw_write(C.byref(m), m.plan.base+m.plan.iat_rva, b'X', 1), 0)
        self.assertEqual(self.lib.cw_run(C.byref(m), 1000), 0)

    def test_reference_rejects_changed_bytes_even_with_matching_new_digest(self):
        folder = self.directory/'imports-reference';folder.mkdir(exist_ok=True)
        image = import_fixture();(folder/'api-set.exe').write_bytes(image)
        receipt = dict(schema='compact-windows-w7-imports-reference/v1', source_commit='a'*40,
                       sha256=hashlib.sha256(image).hexdigest(), exit_code=37,
                       stdout_hex='', stderr_hex='', platform='Windows-test', arch='AMD64')
        with patch('compact_windows_w7_imports.subprocess.check_output', return_value='a'*40+'\n'):
            (folder/'api-set-reference.json').write_text(json.dumps(receipt))
            self.assertEqual(verify_reference(folder), receipt)
            for key, value in (('source_commit', 'b'*40), ('exit_code', 0), ('arch', 'ARM64'), ('platform', 'Linux-test')):
                (folder/'api-set-reference.json').write_text(json.dumps({**receipt, key: value}))
                with self.assertRaises(ValueError):verify_reference(folder)
            changed = image[:-1]+bytes([image[-1]^1]);(folder/'api-set.exe').write_bytes(changed)
            (folder/'api-set-reference.json').write_text(json.dumps({**receipt, 'sha256': hashlib.sha256(changed).hexdigest()}))
            with self.assertRaises(ValueError):verify_reference(folder)


if __name__ == '__main__':
    unittest.main()
