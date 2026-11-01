# SPDX-License-Identifier: AGPL-3.0-only
import ctypes
import subprocess
import tempfile
import copy
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from compact_windows_w6_native import case_specs,parse_cases,standalone,required_calls,fault_specs,verify_dedicated_resource_reboot

def serial(specs):
    lines=[]
    for name,spec in specs.items():
        lines.append('CW_CASE_'+name+'_BEGIN')
        if spec.get('admission'):lines.append(f"CW_NATIVE status={spec['status']} executed=0 admission=1")
        else:
            record=dict(status=spec['status'],executed=1,exited=int(spec['status']==0),code=spec.get('code') or 0,steps=spec.get('steps',100),stop='ok',ip=0x140001000,owned=1200000,guest=1150976,open=0,peak_handles=30 if name=='handle-limit' else 1,heap=1048576 if name=='heap-limit' else 0,flushes=2 if name=='durable' else 0,error=50 if name in ('file','unsynced') else 5 if name=='readonly' else 1117 if name in fault_specs() else 0)
            lines.append('CW_NATIVE '+' '.join(f'{k}={v}' for k,v in record.items()))
            lines+=['CW_OUT '+spec['out'],'CW_ERR '+spec['err']]
            lines += ['CW_CALL '+api+' '+str(count) for api,count in required_calls(name).items()]
        lines.append('CW_CASE_'+name+'_END')
    return ('\n'.join(lines)+'\n').encode()
class NativeEvidenceTests(unittest.TestCase):
    def test_finite_case_set_accepts_complete_records(self):
        cases=case_specs();self.assertEqual(len(parse_cases(serial(cases),cases)),len(cases));self.assertGreaterEqual(len(cases),18)
    def test_command_echo_cannot_stand_in_for_native_output(self):
        self.assertFalse(standalone(b'term% echo CW_NATIVE_BUILD_OK\r\n','CW_NATIVE_BUILD_OK'))
        self.assertTrue(standalone(b'term% echo x\r\nCW_NATIVE_BUILD_OK\r\n','CW_NATIVE_BUILD_OK'))
        with self.assertRaises(ValueError):parse_cases(b'term% echo CW_CASE_api_BEGIN; echo CW_CASE_api_END\r\n',{'api':case_specs()['api']})
    def test_false_success_or_hidden_leaks_are_rejected(self):
        cases=case_specs();good=serial(cases)
        for old,new in [(b'status=8 ',b'status=0 '),(b'open=0 ',b'open=1 '),(b'guest=1150976 ',b'guest=67108865 '),(b'peak_handles=30 ',b'peak_handles=29 '),(b'heap=1048576 ',b'heap=1044480 '),(b'error=50',b'error=0'),(b'CW_CALL CreateFileW 31',b'CW_CALL CreateFileW 30'),(b'CW_CALL malloc 2',b'CW_CALL malloc 0'),(b'flushes=2',b'flushes=1')]:
            with self.subTest(old=old):
                with self.assertRaises(ValueError):parse_cases(good.replace(old,new),cases)
    def test_storage_failure_receipts_cannot_claim_flush_success(self):
        cases=fault_specs();good=serial(cases)
        self.assertEqual(set(parse_cases(good,cases)),set(cases))
        for old,new in ((b'error=1117',b'error=0'),(b'flushes=0',b'flushes=1')):
            with self.assertRaises(ValueError):parse_cases(good.replace(old,new),cases)
    def test_native_case_output_is_exact_and_admission_does_not_execute(self):
        cases=case_specs();good=serial(cases)
        with self.assertRaises(ValueError):parse_cases(good.replace(b'admission=1',b'admission=0'),cases)
        with self.assertRaises(ValueError):parse_cases(good.replace(b'CW_OUT ',b'CW_OUT ff',1),cases)
class CrashPersistenceScopeTests(unittest.TestCase):
    def test_only_acknowledged_resource_disk_required_after_hardcut(self):
        runtime='a'*64
        durable='b'*64
        log=('Ryzova Kernel 0.1.0-dev\n'+runtime+'\t/amd64/bin/compact-windows\n'
             'CW_REBOOT_IDENTITY_OK\nCW_REBOOT_RESOURCE_MOUNTED\n'
             +durable+'\t/tmp/cw-durable/payload.bin\nCW_REBOOT_DONE\n').encode()
        self.assertTrue(verify_dedicated_resource_reboot(log,runtime,durable))
        for bad in (
            log.replace(durable.encode(),b'c'*64),
            log.replace(runtime.encode(),b'c'*64),
            log.replace(b'CW_REBOOT_RESOURCE_MOUNTED\n',b''),
            log.replace(b'CW_REBOOT_DONE\n',b''),
            log.replace(b'Ryzova Kernel 0.1.0-dev',b'Other OS'),
        ):
            with self.subTest(bad=bad[-90:]),self.assertRaises(ValueError):
                verify_dedicated_resource_reboot(bad,runtime,durable)
        # Echoing a command is NOT proof that the event took place.
        echo=b'term% echo CW_REBOOT_DONE\n'+log.replace(b'CW_REBOOT_DONE\n',b'')
        with self.assertRaises(ValueError):
            verify_dedicated_resource_reboot(echo,runtime,durable)

class BarrierProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory();binary=Path(cls.directory.name)/'protocol.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-shared','-fPIC','-fsanitize=undefined','-fno-sanitize-recover=all',str(ROOT/'ryzova/compat/windows/sync_protocol.c'),'-o',str(binary)],check=True)
        cls.lib=ctypes.CDLL(str(binary))
        cls.lib.cw_sync_request.argtypes=[ctypes.c_ulonglong,ctypes.c_void_p]
        cls.lib.cw_sync_reply.argtypes=[ctypes.c_ulonglong,ctypes.c_void_p]
        cls.lib.cw_sync_ack.argtypes=[ctypes.c_char_p,ctypes.c_uint,ctypes.c_ulonglong]
        cls.lib.cw_sync_parse.argtypes=[ctypes.c_char_p,ctypes.c_uint,ctypes.POINTER(ctypes.c_ulonglong)]
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()
    def test_zero_and_full_width_nonce_roundtrip(self):
        for nonce in (0,1,0xabcdef0123456789,2**64-1):
            request=ctypes.create_string_buffer(22);reply=ctypes.create_string_buffer(21);decoded=ctypes.c_ulonglong()
            self.lib.cw_sync_request(nonce,request);self.lib.cw_sync_reply(nonce,reply)
            self.assertTrue(self.lib.cw_sync_parse(request.raw,22,ctypes.byref(decoded)));self.assertEqual(decoded.value,nonce)
            self.assertTrue(self.lib.cw_sync_ack(reply.raw,21,nonce))
    def test_echo_stale_truncated_and_extended_reply_fail_closed(self):
        for data in (b'SYNC 0000000000000001\n',b'ACK 0000000000000000\n',b'ACK 0000000000000001',b'ACK 0000000000000001\nextra',b'ACK 000000000000000g\n'):
            self.assertFalse(self.lib.cw_sync_ack(data,len(data),1))
    def test_malformed_request_cannot_change_nonce(self):
        for data in (b'',b'SYNC 0000000000000001',b'SYNC 0000000000000001\nextra',b'SYNC 000000000000000G\n',b'ACK 0000000000000001\n',b'SYNC 00000000\x000000001\n'):
            decoded=ctypes.c_ulonglong(99)
            self.assertFalse(self.lib.cw_sync_parse(data,len(data),ctypes.byref(decoded)));self.assertEqual(decoded.value,99)
if __name__=='__main__':unittest.main()
