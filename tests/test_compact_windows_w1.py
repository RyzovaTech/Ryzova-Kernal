# SPDX-License-Identifier: AGPL-3.0-only
"""W1 contract/boundary checks are not Windows execution qualification."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'scripts')]
from ryzova.compat.windows.contract_v1 import validate_request,ContractError,LIMITS,APIS
from compact_windows_w1 import audit

def request():
    return {'schema':'compact-windows-request/v1','environment':'compact/windows',
            'api_major':1,'api_minor':0,'abi':'windows-amd64-pe32plus-v1',
            'profile':'console-win32-v1','apis':['KERNEL32.DLL!WriteFile'],
            'resources':[{'ref':'stdout','kind':'console','rights':['write']}],'limits':{}}
class WindowsW1Tests(unittest.TestCase):
    def test_valid_request_is_only_shape_validation_never_execution_or_authority(self):
        result=validate_request(request());self.assertFalse(result['execution_available']);self.assertFalse(result['authority_attached']);self.assertFalse(result['windows_execution_qualified']);self.assertEqual(result['status'],'contract-only')
        self.assertEqual(result['request']['apis'],['kernel32.dll!WriteFile'])
    def test_linux_mac_and_alternate_architectures_cannot_negotiate_windows_abi(self):
        for key,value in [('environment','compact/linux'),('environment','compact/mac'),('abi','linux-amd64'),('abi','windows-arm64'),('profile','full-windows')]:
            with self.subTest(key=key,value=value):
                data=request();data[key]=value
                with self.assertRaises(ContractError):validate_request(data)
    def test_version_bool_and_unimplemented_versions_are_denied(self):
        for key,value in [('api_major',True),('api_minor',False),('api_major',2),('api_minor',1),('api_minor',-1)]:
            data=request();data[key]=value
            with self.assertRaises(ContractError):validate_request(data)
    def test_unknown_missing_or_authority_fields_are_denied(self):
        for field in ('privileged','host_path','dll_search_path','native_exec','execution_available'):
            data=request();data[field]=True
            with self.assertRaises(ContractError):validate_request(data)
        for field in request():
            data=request();del data[field]
            with self.assertRaises(ContractError):validate_request(data)
    def test_imports_require_declared_case_sensitive_export_and_no_ordinals(self):
        for api in ('kernel32.dll!writefile','kernel32.dll!CreateProcessW','ntdll.dll!NtCreateFile','ucrtbase.dll!puts','kernel32.dll!#123','../kernel32.dll!WriteFile'):
            data=request();data['apis']=[api]
            with self.assertRaises(ContractError):validate_request(data)
        data=request();data['apis']=['KERNEL32.DLL!WriteFile','kernel32.dll!WriteFile']
        with self.assertRaises(ContractError):validate_request(data)
    def test_non_string_imports_are_denied_without_type_errors(self):
        for value in (None,{},[],1,True):
            data=request();data['apis']=[value]
            with self.assertRaises(ContractError):validate_request(data)
    def test_grant_references_never_accept_host_paths_or_traversal(self):
        for ref in ('../host','C:\\Windows','/srv/project','\\\\server\\share','a..b','a\x00b','a'*65):
            data=request();data['resources'][0]['ref']=ref
            with self.assertRaises(ContractError):validate_request(data)
        data=request();data['resources'][0]['host_path']='/tmp'
        with self.assertRaises(ContractError):validate_request(data)
    def test_resource_rights_kinds_duplicates_and_unbounded_requests_are_denied(self):
        for field,value in [('kind','device'),('rights',['read']),('rights',['write','write']),('rights',[]),('rights','write'),('ref',{})]:
            data=request();data['resources'][0][field]=value
            with self.assertRaises(ContractError):validate_request(data)
        data=request();data['resources']*=2
        with self.assertRaises(ContractError):validate_request(data)
    def test_every_limit_rejects_bool_zero_and_overflow(self):
        for key,maximum in LIMITS.items():
            for value in (True,0,-1,maximum+1,'unlimited'):
                with self.subTest(key=key,value=value):
                    data=request();data['limits']={key:value}
                    with self.assertRaises(ContractError):validate_request(data)
        data=request();data['limits']={'cpu_seconds':0}
        with self.assertRaises(ContractError):validate_request(data)
    def test_dependent_limits_and_import_counts_are_checked(self):
        for limits in ({'guest_memory_bytes':1024},{'aggregate_image_buffers_bytes':1024},{'imports':1}):
            data=request();data['limits']=limits
            if 'imports' in limits:data['apis'].append('kernel32.dll!ExitProcess')
            with self.assertRaises(ContractError):validate_request(data)
    def test_normalized_request_does_not_alias_caller_state(self):
        data=request();before=deepcopy(data);out=validate_request(data);out['request']['resources'][0]['rights'].append('read');self.assertEqual(data,before)
    def test_audit_records_existing_metadata_gaps_without_marking_execution_passed(self):
        report=audit();self.assertFalse(report['windows_execution_qualified']);self.assertEqual(len(report['cases']),7)
        for item in report['cases']:
            self.assertEqual(item['probe_exit'],0,item);self.assertFalse(item['execution_attempted']);self.assertIn('not executed',item['observed'])
    def test_finite_plan_has_six_ordered_phases_and_no_false_runtime_gates(self):
        plan=json.loads((ROOT/'ryzova/compact/windows-v1-plan.json').read_text())
        self.assertEqual([x['id'] for x in plan['phases']],['W1','W2','W3','W4','W5','W6'])
        self.assertFalse(plan['windows_execution_qualified']);self.assertFalse(plan['general_windows_compatibility_claim'])
        for gate in plan['requirements']:self.assertEqual(gate['state'],'pending')
        self.assertEqual(plan['limits'],LIMITS);self.assertEqual(plan['planned_apis'],APIS)
    def test_audit_snapshot_pins_the_actual_baseline_sources(self):
        receipt=json.loads((ROOT/'docs/validation/compact-windows-w1-audit.json').read_text());current=audit()
        self.assertEqual(receipt['source_sha256'],current['source_sha256']);self.assertEqual(receipt['cases'],current['cases']);self.assertFalse(receipt['windows_execution_qualified'])
if __name__=='__main__':unittest.main()
