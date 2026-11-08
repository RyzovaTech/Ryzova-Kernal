# SPDX-License-Identifier: GPL-3.0-only
"""SSE4 instructions required by the pinned SQLite shell."""
import ctypes as C
import struct
import unittest
import test_compact_windows_w2 as w2
from compact_windows_w2 import pe


class SQLiteInstructions(unittest.TestCase):
    setUpClass = classmethod(w2.WindowsW2Tests.setUpClass.__func__)
    tearDownClass = classmethod(w2.WindowsW2Tests.tearDownClass.__func__)
    loaded = w2.WindowsW2Tests.loaded
    admitted = w2.WindowsW2Tests.admitted

    def machine(self, code):
        return self.loaded(pe(bytes.fromhex(code)+b'\xc3'))

    def test_ptest_flags_and_unchanged_vectors(self):
        for a, b in ((0, 0), (0, 255), (255, 0), (255, 255), (15, 240), (15, 31)):
            with self.subTest(a=a, b=b):
                m, arena = self.machine('660f3817c1')
                m.xmm[0][:] = bytes([a])*16
                m.xmm[1][:] = bytes([b])*16
                m.flags = 0xfff
                self.assertEqual(self.lib.cw_run(C.byref(m), 20), 0)
                wanted = (0 if a & b else 64) | (0 if (~a & b) else 1)
                self.assertEqual(m.flags & 0x8d5, wanted)
                self.assertEqual(bytes(m.xmm[0]), bytes([a])*16)
                self.assertEqual(bytes(m.xmm[1]), bytes([b])*16)

    def test_pmovzxbd_alias_and_extended_registers(self):
        for code, dst, src in (('660f3831c0', 0, 0), ('660f3831c1', 0, 1), ('66450f3831c1', 8, 9)):
            m, arena = self.machine(code)
            m.xmm[dst][:] = bytes([255])*16
            m.xmm[src][:] = bytes([0, 127, 128, 255])+bytes([233])*12
            before = bytes(m.xmm[src])
            self.assertEqual(self.lib.cw_run(C.byref(m), 20), 0)
            self.assertEqual(bytes(m.xmm[dst]), struct.pack('<4I', 0, 127, 128, 255))
            if src != dst:
                self.assertEqual(bytes(m.xmm[src]), before)

    def test_pinsrb_all_register_sources_and_lane_mask(self):
        # r/m selects an r32 source: 4..7 select ESP..EDI, never AH..BH.
        for reg in range(8):
            for lane in (0, 1, 15, 255):
                m, arena = self.machine('660f3a20'+bytes([0xc0+reg, lane]).hex())
                before = m.r[reg]
                if reg != 4:
                    m.r[reg] = 0x1234ab80+reg
                expected = m.r[reg] & 255
                m.xmm[0][:] = bytes(range(16))
                self.assertEqual(self.lib.cw_run(C.byref(m), 1), 8)
                wanted = bytearray(range(16)); wanted[lane & 15] = expected
                self.assertEqual(bytes(m.xmm[0]), wanted)
                if reg == 4:
                    self.assertEqual(m.r[4], before)

    def test_memory_alignment_and_short_load_boundaries(self):
        for code, offset, status in (('660f381700', 0, 0),
                                     ('660f381700', 1, 6),
                                     ('660f383100', 4092, 0),
                                     ('660f383100', 4093, 6),
                                     ('660f3a20000f', 4095, 0),
                                     ('660f3a20000f', 4096, 6)):
            m, arena = self.loaded(pe(bytes.fromhex(code)+b'\xc3', bytes(4096)))
            m.r[0] = m.plan.base+0x2000+offset
            m.xmm[0][:] = bytes([255])*16
            self.assertEqual(self.lib.cw_run(C.byref(m), 20), status)
            if status:
                self.assertEqual(bytes(m.xmm[0]), bytes([255])*16)

    def test_unsupported_sse4_encoding_stays_denied(self):
        for code in ('660f3830c1', '660f3a21c100'):
            m, arena = self.machine(code)
            self.assertEqual(self.lib.cw_run(C.byref(m), 20), 7)


if __name__ == '__main__':
    unittest.main()
