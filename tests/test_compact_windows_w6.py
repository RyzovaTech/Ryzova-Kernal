# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from compact_windows_w6_native import case_specs,parse_cases,standalone

def serial(specs):
    lines=[]
    for name,spec in specs.items():
        lines.append('CW_CASE_'+name+'_BEGIN')
        if spec.get('admission'):lines.append(f"CW_NATIVE status={spec['status']} executed=0 admission=1")
        else:
            record=dict(status=spec['status'],executed=1,exited=int(spec['status']==0),code=spec.get('code') or 0,steps=spec.get('steps',100),stop='ok',ip=0x140001000,owned=1200000,guest=1150976,open=0,peak_handles=30 if name=='handle-limit' else 1,heap=1048576 if name=='heap-limit' else 0,error=50 if name in ('file','unsynced') else 5 if name=='readonly' else 0)
            lines.append('CW_NATIVE '+' '.join(f'{k}={v}' for k,v in record.items()))
            lines+=['CW_OUT '+spec['out'],'CW_ERR '+spec['err']]
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
        for old,new in [(b'status=8 ',b'status=0 '),(b'open=0 ',b'open=1 '),(b'guest=1150976 ',b'guest=67108865 '),(b'peak_handles=30 ',b'peak_handles=29 '),(b'heap=1048576 ',b'heap=1044480 '),(b'error=50',b'error=0')]:
            with self.subTest(old=old):
                with self.assertRaises(ValueError):parse_cases(good.replace(old,new),cases)
    def test_native_case_output_is_exact_and_admission_does_not_execute(self):
        cases=case_specs();good=serial(cases)
        with self.assertRaises(ValueError):parse_cases(good.replace(b'admission=1',b'admission=0'),cases)
        with self.assertRaises(ValueError):parse_cases(good.replace(b'CW_OUT ',b'CW_OUT ff',1),cases)
if __name__=='__main__':unittest.main()
