# SPDX-License-Identifier: AGPL-3.0-only
"""W8 real bounded guest GetCurrentProcessId / GetCurrentThreadId APIs.

They return namespace-local synthetic IDs in the declared one-process,
one-thread compact Windows environment; never host PID/TID, never a
claim of Windows process/thread creation or scheduling compatibility.
"""
import ctypes as C
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"scripts"),str(ROOT/"tests")]
import test_compact_windows_w3 as w3
from compact_windows_w3 import imported_pe
from compact_windows_w2 import PREFERRED

VIRTUAL_IDS=("GetCurrentProcessId","GetCurrentThreadId")
MASK=(1<<30)-1


class W8VirtualIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=w3.WindowsW3Tests("test_last_error_is_per_machine_and_dword_sized")
        cls.base.setUpClass()
        cls.lib=cls.base.lib
        cls.lib.cw_api_id.argtypes=[C.c_char_p]
        cls.lib.cw_api_id.restype=C.c_int
        cls.lib.cw_api_module.argtypes=[C.c_uint]
        cls.lib.cw_api_module.restype=C.c_char_p
        cls.lib.cw_api_token.argtypes=[C.c_uint]
        cls.lib.cw_api_token.restype=C.c_uint64

    @classmethod
    def tearDownClass(cls):
        cls.base.temp.cleanup()

    def context(self,mask=MASK):
        cfg=w3.launch()
        cfg.api_mask=mask
        return self.base.context(cfg,blob=imported_pe(
            b"\\xc3",names=VIRTUAL_IDS,payload=bytes(512)))

    def invoke(self,ctx,api):
        m,s,arena,heap=ctx
        identity=self.lib.cw_api_id(api.encode("ascii"))
        self.assertIn(identity,(28,29))
        m.exited=0
        m.status=0
        m.ip=self.lib.cw_api_token(identity)
        m.r[4]=m.initial_sp-64
        self.assertEqual(self.lib.cw_write(C.byref(m),m.r[4],
                         struct.pack("<Q",PREFERRED+0x1000),8),0)
        before=m.r[4]
        result=self.lib.cw_api_dispatch(C.byref(m))
        self.assertEqual(result,0,(api,result))
        self.assertEqual(m.r[4],before+8)
        return m.r[0]

    def test_modules_and_virtual_ids_are_separate_from_host_processes(self):
        first=self.context()
        second=self.context()
        for api,id_ in zip(VIRTUAL_IDS,(28,29)):
            self.assertEqual(self.lib.cw_api_id(api.encode("ascii")),id_)
            self.assertEqual(self.lib.cw_api_module(id_),b"kernel32.dll")
            first[1].last_error=0x76543210
            self.assertEqual(self.invoke(first,api),1)
            self.assertEqual(self.invoke(first,api),1)
            self.assertEqual(self.invoke(second,api),1)
            self.assertEqual(first[1].last_error,0x76543210)
            self.assertEqual(first[1].calls[id_],2)
            self.assertEqual(second[1].calls[id_],1)
        self.assertIsNone(self.lib.cw_api_module(30))
        self.assertEqual(self.lib.cw_api_id(b"CreateProcessW"),-1)

    def test_missing_authorization_rejects_before_guest_execution(self):
        cfg=w3.launch()
        cfg.api_mask=(1<<28)-1
        m,arena=self.base.loaded(imported_pe(
            b"\\xc3",names=VIRTUAL_IDS,payload=bytes(512)))
        s=w3.Services()
        heap=C.create_string_buffer(4096)
        self.assertEqual(self.lib.cw_attach_services(C.byref(m),C.byref(s),
                         C.byref(cfg),heap,4096),10)
        self.assertFalse(m.services)
        self.assertEqual(bytes(arena[:4]),bytes(arena[:4]))

if __name__=="__main__":
    unittest.main()
