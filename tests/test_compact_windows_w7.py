# SPDX-License-Identifier: AGPL-3.0-only
"""TLS executes guest instructions, preserves isolation and fails closed."""
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
from compact_windows_w2 import pe, PREFERRED
from compact_windows_w7_tls import tls_fixture, verify_reference, TLS_READ, TLS_DIRECTORY, TLS_CALLBACK_ARRAY


class WindowsW7TlsTests(unittest.TestCase):
    setUpClass = classmethod(w2.WindowsW2Tests.setUpClass.__func__)
    tearDownClass = classmethod(w2.WindowsW2Tests.tearDownClass.__func__)
    admitted = w2.WindowsW2Tests.admitted
    loaded = w2.WindowsW2Tests.loaded
    denied = w2.WindowsW2Tests.denied
    mutate = w2.WindowsW2Tests.mutate
    run_pe = w2.WindowsW2Tests.run_pe

    def raw(self, image, rva):
        count = struct.unpack_from('<H', image, 0x86)[0]
        for i in range(count):
            vs, at, size, raw = struct.unpack_from('<IIII', image, 0x188+i*40+8)
            if at <= rva < at+size:
                return raw+rva-at
        raise ValueError(hex(rva))

    def test_callbacks_execute_in_order_before_entry_with_windows_arguments(self):
        for callbacks in (0, 1, 2, 8):
            with self.subTest(callbacks=callbacks):
                m, arena = self.loaded(tls_fixture(callbacks=callbacks))
                self.assertEqual(self.lib.cw_run(C.byref(m), 1000), 0)
                self.assertEqual((m.exited, m.exit_code), (1, 7+callbacks))
                self.assertEqual(struct.unpack_from('<I', arena.raw, 0x2024)[0], callbacks)

    def test_template_zero_fill_teb_index_and_machine_isolation(self):
        image = tls_fixture()
        m, arena = self.loaded(image)
        other, other_arena = self.loaded(image)
        stack = C.string_at(m.stack, 8192)
        self.assertEqual(struct.unpack_from('<Q', stack, 0x30)[0], m.stack_base)
        self.assertEqual(struct.unpack_from('<Q', stack, 0x58)[0], m.stack_base+0x800)
        self.assertEqual(struct.unpack_from('<Q', stack, 0x800)[0], m.stack_base+0x1000)
        self.assertEqual(struct.unpack_from('<I', arena.raw, 0x2020)[0], 0)
        self.assertEqual(stack[0x1000:0x1018], struct.pack('<II', 7, 0x13579bdf)+bytes(16))
        self.assertEqual(self.lib.cw_run(C.byref(m), 1000), 0)
        self.assertEqual(C.string_at(other.stack+0x1000, 4), struct.pack('<I', 7))
        self.assertEqual(struct.unpack_from('<I', other_arena.raw, 0x2024)[0], 0)
        self.assertNotEqual(self.lib.cw_read(C.byref(m), m.stack_base+0x1000, C.create_string_buffer(1), 1, 4), 0)

    def test_template_limit_and_zero_only_tls(self):
        m, arena = self.loaded(tls_fixture(callbacks=0, zero=4088))
        self.assertEqual(C.string_at(m.stack+0x1008, 4088), bytes(4088))
        image = tls_fixture(callbacks=0)
        d = self.raw(image, TLS_DIRECTORY)
        image = self.mutate(d, 'Q', 0, image)
        image = self.mutate(d+8, 'Q', 0, image)
        image = self.mutate(d+24, 'Q', 0, image)
        m, arena = self.loaded(image)
        self.assertEqual(self.lib.cw_run(C.byref(m), 100), 0)
        self.assertEqual((m.exited, m.exit_code), (1, 0))

    def test_callback_can_tail_call_declared_guest_api(self):
        from test_compact_windows_w3 import Services, Launch, launch
        self.lib.cw_attach_services.argtypes = [C.POINTER(w2.Machine), C.POINTER(Services), C.POINTER(Launch), C.c_void_p, C.c_size_t]
        self.lib.cw_attach_services.restype = C.c_int
        callback = b'\xff\x25'+struct.pack('<i', 0x2090-0x1106)
        image = bytearray(tls_fixture(callbacks=1, callback_code=callback))
        data = self.raw(image, 0x2000)
        struct.pack_into('<IIIII', image, data+64, 0x2080, 0, 0, 0x20d0, 0x2090)
        struct.pack_into('<Q', image, data+128, 0x20b0)
        struct.pack_into('<Q', image, data+144, 0x20b0)
        image[data+176:data+176+15] = b'\0\0GetLastError\0'
        image[data+208:data+208+13] = b'KERNEL32.dll\0'
        struct.pack_into('<II', image, 0x98+112+8, 0x2040, 40)
        struct.pack_into('<II', image, 0x98+112+12*8, 0x2090, 16)
        m, arena = self.loaded(bytes(image))
        services = Services();heap = C.create_string_buffer(4096);policy = launch()
        self.assertEqual(self.lib.cw_attach_services(C.byref(m), C.byref(services), C.byref(policy), heap, len(heap)), 0)
        self.assertEqual(self.lib.cw_run(C.byref(m), 100), 0)
        self.assertEqual((m.exited, m.exit_code, services.calls[3]), (1, 7, 1))
        d = self.raw(image, TLS_DIRECTORY)
        bad = self.mutate(d+16, 'Q', PREFERRED+0x2090, image)
        self.denied(bad)
        self.denied(self.mutate(0x98+112+12*8, 'II', (0, 0), bad))

    def test_actual_relocation_of_callback_code_and_tls_template(self):
        image = tls_fixture()
        for base in (PREFERRED, PREFERRED+0x40000000, PREFERRED-0x40000000):
            with self.subTest(base=base):
                result = self.run_pe(image, base)
                self.assertEqual((result['status'], result['exit_code'], result['nonvolatile_preserved']), (0, 9, True))

    def test_fault_budget_and_unbalanced_callback_never_reach_entry(self):
        for callback, budget, expected in ((b'\x0f\x0b', 100, 7), (b'\xeb\xfe', 30, 8),
                                           (b'\x48\x83\xec\x08\x48\xb8'+struct.pack('<Q', 0xfffffffffffffffe)+b'\x50\xc3', 100, 9)):
            with self.subTest(callback=callback):
                m, arena = self.loaded(tls_fixture(callback_code=callback))
                self.assertEqual(self.lib.cw_run(C.byref(m), budget), expected)
                self.assertFalse(m.exited)
                self.assertEqual(struct.unpack_from('<I', arena.raw, 0x2024)[0], 0)

    def test_entry_cannot_replay_trusted_callback_return(self):
        entry = b'\x48\xb8'+struct.pack('<Q', 0xfffffffffffffffe)+b'\x48\x89\x04\x24\xc3'
        m, arena = self.loaded(tls_fixture(entry=entry))
        self.assertEqual(self.lib.cw_run(C.byref(m), 1000), 9)
        self.assertFalse(m.exited)

    def test_tls_metadata_adversarial_bounds_and_permissions(self):
        image = tls_fixture()
        d = self.raw(image, TLS_DIRECTORY)
        cb = self.raw(image, TLS_CALLBACK_ARRAY)
        for offset, fmt, value in (
            (0x98+112+9*8+4, 'I', 39), (0x98+112+9*8, 'I', TLS_DIRECTORY+1),
            (d, 'Q', PREFERRED-1), (d+8, 'Q', PREFERRED+0x1fff),
            (d+8, 'Q', PREFERRED+0x4000), (d+32, 'I', 4096),
            (d+36, 'I', 1), (d+36, 'I', 0x00e00000),
            (d+16, 'Q', PREFERRED+0x1000), (d+16, 'Q', PREFERRED+0x2021),
            (d+16, 'Q', PREFERRED+0x23fe), (d+24, 'Q', PREFERRED+TLS_CALLBACK_ARRAY+1),
            (d+24, 'Q', PREFERRED+0x2000), (cb, 'Q', PREFERRED+0x2000),
            (cb, 'Q', PREFERRED+0x1fff), (cb, 'Q', 0xfffffffffffffffe),
            (0x188+2*40+36, 'I', 0xc0000040),
        ):
            with self.subTest(offset=offset, value=value):
                self.denied(self.mutate(offset, fmt, value, image))
        self.denied(tls_fixture(callbacks=9))

    def test_gs_bounds_and_lea_semantics(self):
        # LEA computes an offset without applying the GS base.
        result = self.run_pe(tls_fixture(callbacks=0, entry=bytes.fromhex('65 48 8d 04 25 58 00 00 00 c3')))
        self.assertEqual((result['status'], result['exit_code']), (0, 0x58))
        for entry in (bytes.fromhex('65 48 8b 04 25 ff ff ff ff c3'),
                      bytes.fromhex('65 48 8b 04 25 00 00 02 00 c3')):
            result = self.run_pe(tls_fixture(callbacks=0, entry=entry))
            self.assertEqual(result['status'], 6)
        self.assertEqual(self.run_pe(pe(TLS_READ+b'\xc3'))['status'], 6)

    def test_windows_reference_is_bound_to_exact_bytes_commit_and_result(self):
        folder = self.directory/'reference';folder.mkdir(exist_ok=True)
        image = tls_fixture();(folder/'tls.exe').write_bytes(image)
        receipt = dict(schema='compact-windows-w7-tls-reference/v1', source_commit='a'*40,
                       sha256=hashlib.sha256(image).hexdigest(), exit_code=9,
                       stdout_hex='', stderr_hex='', platform='Windows-test', arch='AMD64')
        with patch('compact_windows_w7_tls.subprocess.check_output', return_value='a'*40+'\n'):
            (folder/'tls-reference.json').write_text(json.dumps(receipt))
            self.assertEqual(verify_reference(folder), receipt)
            for key, value in (('source_commit', 'b'*40), ('sha256', '0'*64), ('exit_code', 0),
                               ('stdout_hex', '00'), ('stderr_hex', '00'), ('arch', 'ARM64'),
                               ('platform', 'Linux-test'), ('schema', 'other')):
                with self.subTest(key=key):
                    (folder/'tls-reference.json').write_text(json.dumps({**receipt, key: value}))
                    with self.assertRaises(ValueError):verify_reference(folder)
            altered = image[:-1]+bytes([image[-1]^1])
            (folder/'tls.exe').write_bytes(altered)
            (folder/'tls-reference.json').write_text(json.dumps({**receipt, 'sha256': hashlib.sha256(altered).hexdigest()}))
            with self.assertRaises(ValueError):verify_reference(folder)


if __name__ == '__main__':
    unittest.main()
