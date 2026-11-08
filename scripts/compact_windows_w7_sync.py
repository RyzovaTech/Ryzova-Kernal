# SPDX-License-Identifier: GPL-3.0-only
"""Guest synchronization/handle lifetime comparison with Windows."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
from compact_windows_w2 import ROOT
from compact_windows_w5 import imported_pe_modules, build
from compact_windows_w7_startup import execute

SYNC_APIS = ('CreateEventA', 'SetEvent', 'ResetEvent', 'CreateSemaphoreA', 'ReleaseSemaphore',
             'WaitForSingleObject', 'WaitForMultipleObjects', 'InitializeCriticalSection',
             'DeleteCriticalSection', 'EnterCriticalSection', 'LeaveCriticalSection',
             'TryEnterCriticalSection', 'GetCurrentProcess', 'GetCurrentProcessId',
             'GetCurrentThread', 'GetCurrentThreadId', 'DuplicateHandle')
APIS = (*SYNC_APIS, 'CloseHandle', 'GetLastError')
LOW_MASK = 0x808
HIGH_MASK = 0xffff8
EXPECTED_CALLS = dict(CreateEventA=3, SetEvent=4, ResetEvent=2, CreateSemaphoreA=1,
                      ReleaseSemaphore=3, WaitForSingleObject=9, WaitForMultipleObjects=5,
                      InitializeCriticalSection=1, DeleteCriticalSection=1, EnterCriticalSection=2,
                      LeaveCriticalSection=3, TryEnterCriticalSection=1, GetCurrentProcess=1,
                      GetCurrentProcessId=1, GetCurrentThread=1, GetCurrentThreadId=1,
                      DuplicateHandle=3, CloseHandle=5, GetLastError=2)


def sync_fixture(blocking=False):
    code = bytearray(b'\x48\x83\xec\x38');branches = []
    def emit(raw):code.extend(raw)
    def rel(op, rva):emit(op+struct.pack('<i', rva-(0x1000+len(code)+len(op)+4)))
    def call(name):rel(b'\xff\x15', 0x2280+APIS.index(name)*8)
    def imm(reg, value):emit({'cx':b'\xb9','dx':b'\xba','r8':b'\x41\xb8','r9':b'\x41\xb9'}[reg]+struct.pack('<I', value))
    def load(reg, rva):rel({'cx':b'\x48\x8b\x0d','dx':b'\x48\x8b\x15','r8':b'\x4c\x8b\x05'}[reg], rva)
    def lea(reg, rva):rel({'cx':b'\x48\x8d\x0d','r8':b'\x4c\x8d\x05','r9':b'\x4c\x8d\x0d','dx':b'\x48\x8d\x15'}[reg], rva)
    def fail(condition):branches.append(len(code));emit(b'\x0f'+bytes([condition])+bytes(4))
    def truth(want=True,pointer=False):emit(b'\x48\x85\xc0' if pointer else b'\x85\xc0');fail(0x84 if want else 0x85)
    def equal(value):emit(b'\x3d'+struct.pack('<I', value));fail(0x85)
    def save(rva):rel(b'\x48\x89\x05', rva)
    def event(rva, manual, initial):
        imm('cx',0);imm('dx',manual);imm('r8',initial);imm('r9',0);call('CreateEventA');truth(pointer=True);save(rva)
    def wait(rva, result, timeout=0):load('cx',rva);imm('dx',timeout);call('WaitForSingleObject');equal(result)
    def action(name, rva, want=True):load('cx',rva);call(name);truth(want)
    def multi(all, result):
        imm('cx',2);lea('dx',0x2c20);imm('r8',all);imm('r9',0);call('WaitForMultipleObjects');equal(result)
    def duplicate(source, out, target=0x2c30, options=2):
        load('cx',0x2c30);load('dx',source)
        if target == 0x2c30:load('r8',target)
        else:imm('r8',target)
        lea('r9',out)
        for offset, value in ((32,0),(40,0),(48,options)):
            emit(b'\x48\xc7\x44\x24'+bytes([offset])+struct.pack('<I',value))
        call('DuplicateHandle')
    event(0x2c00,0,0)
    if blocking:
        load('cx',0x2c00);imm('dx',0xffffffff);call('WaitForSingleObject')
    else:
        wait(0x2c00,258);action('SetEvent',0x2c00);wait(0x2c00,0);wait(0x2c00,258)
        event(0x2c08,1,1);wait(0x2c08,0);wait(0x2c08,0)
        action('ResetEvent',0x2c08);wait(0x2c08,258)
        imm('cx',0);imm('dx',1);imm('r8',2);imm('r9',0);call('CreateSemaphoreA');truth(pointer=True);save(0x2c10)
        load('cx',0x2c10);imm('dx',2);lea('r8',0x2c68);call('ReleaseSemaphore');truth(False)
        call('GetLastError');equal(298)
        load('cx',0x2c10);imm('dx',1);lea('r8',0x2c68);call('ReleaseSemaphore');truth()
        rel(b'\x83\x3d',0x2c68);emit(b'\x01') # displacement must account for trailing immediate
        # Correct RIP-relative displacement includes the immediate byte.
        struct.pack_into('<i',code,len(code)-5,0x2c68-(0x1000+len(code)))
        fail(0x85)
        wait(0x2c10,0);action('SetEvent',0x2c08)
        load('cx',0x2c08);rel(b'\x48\x89\x0d',0x2c20)
        load('cx',0x2c10);rel(b'\x48\x89\x0d',0x2c28)
        multi(1,0);multi(0,0);action('ResetEvent',0x2c08);multi(0,258)
        load('cx',0x2c10);imm('dx',1);imm('r8',0);call('ReleaseSemaphore');truth()
        multi(0,1);multi(0,258)
        call('GetCurrentProcess');emit(b'\x48\x83\xf8\xff');fail(0x85);save(0x2c30)
        call('GetCurrentThread');emit(b'\x48\x83\xf8\xfe');fail(0x85);save(0x2c38)
        call('GetCurrentProcessId');truth();call('GetCurrentThreadId');truth()
        duplicate(0x2c00,0x2c18);truth();action('SetEvent',0x2c18)
        action('CloseHandle',0x2c00);wait(0x2c18,0);action('CloseHandle',0x2c18)
        duplicate(0x2c38,0x2c18);truth();wait(0x2c18,258);action('CloseHandle',0x2c18)
        event(0x2c70,0,0);duplicate(0x2c70,0x2c18,target=0x12345678,options=3);truth(False)
        action('SetEvent',0x2c70,False);call('GetLastError');equal(6)
        lea('cx',0x2c40);call('InitializeCriticalSection')
        for name in ('EnterCriticalSection','EnterCriticalSection','TryEnterCriticalSection'):
            lea('cx',0x2c40);call(name)
        truth()
        rel(b'\x83\x3d',0x2c4c);emit(b'\x03')
        struct.pack_into('<i',code,len(code)-5,0x2c4c-(0x1000+len(code)));fail(0x85)
        for _ in range(3):lea('cx',0x2c40);call('LeaveCriticalSection')
        lea('cx',0x2c40);call('DeleteCriticalSection')
        action('CloseHandle',0x2c08);action('CloseHandle',0x2c10)
    emit(b'\xb8\x2b\x00\x00\x00\x48\x83\xc4\x38\xc3')
    failure=len(code);emit(b'\xb8\x7f\x00\x00\x00\x48\x83\xc4\x38\xc3')
    for branch in branches:struct.pack_into('<i',code,branch+2,failure-branch-6)
    return imported_pe_modules(bytes(code), {'KERNEL32.dll': APIS}, payload=bytes(128))


def reference(out):
    if platform.system()!='Windows' or platform.machine().upper() not in ('AMD64','X86_64'):
        raise ValueError('requires Windows AMD64')
    out.mkdir(parents=True,exist_ok=True);image=sync_fixture();binary=out/'sync-api.exe';binary.write_bytes(image)
    run=subprocess.run([str(binary.resolve())],capture_output=True,timeout=10,check=False)
    if (run.returncode,run.stdout,run.stderr)!=(43,b'',b''):raise ValueError(f'Windows sync mismatch: {run!r}')
    receipt=dict(schema='compact-windows-w7-sync-reference/v1',
                 source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                 sha256=hashlib.sha256(image).hexdigest(),exit_code=43,stdout_hex='',stderr_hex='',
                 platform=platform.platform(),arch=platform.machine().upper())
    (out/'sync-api-reference.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')


def verify_reference(ref):
    image=(ref/'sync-api.exe').read_bytes();receipt=json.loads((ref/'sync-api-reference.json').read_text(encoding='utf-8'))
    expected=dict(schema='compact-windows-w7-sync-reference/v1',
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  sha256=hashlib.sha256(image).hexdigest(),exit_code=43,stdout_hex='',stderr_hex='')
    if (image!=sync_fixture() or any(receipt.get(k)!=v for k,v in expected.items()) or
            receipt.get('arch') not in ('AMD64','X86_64') or not str(receipt.get('platform','')).startswith('Windows-')):
        raise ValueError('sync reference bytes/provenance mismatch')
    return receipt


def audit(ref,out):
    receipt=verify_reference(ref)
    with tempfile.TemporaryDirectory() as work:
        probe=build(Path(work)/'probe');result=execute(probe,ref/'sync-api.exe',LOW_MASK,HIGH_MASK)
        if (result.get('status'),result.get('exit_code'),result.get('exited'),result.get('stdout_hex'),result.get('stderr_hex'))!=(0,43,True,'',''):
            raise ValueError(f'sync execution mismatch: {result}')
        if {k:v for k,v in result['api_calls'].items() if v}!=EXPECTED_CALLS:raise ValueError('sync call counts differ')
        denied=execute(probe,ref/'sync-api.exe',LOW_MASK,0)
        if denied!=dict(status=10,executed=False,allocation_bytes=0):raise ValueError('sync policy denial too late')
    out.mkdir(parents=True,exist_ok=True)
    (out/'sync-api-comparison.json').write_text(json.dumps(dict(schema='compact-windows-w7-sync-comparison/v1',
        reference=receipt,execution=result,reference_match=True,jq_execution_verified=False,native_kernel_qualified=False),indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('reference','audit'))
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--reference',type=Path)
    args=parser.parse_args()
    if args.mode=='reference':reference(args.out)
    elif args.reference is None:parser.error('audit requires --reference')
    else:audit(args.reference,args.out)
