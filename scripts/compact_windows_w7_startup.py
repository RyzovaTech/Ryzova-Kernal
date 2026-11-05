# SPDX-License-Identifier: AGPL-3.0-only
"""Stateful file-API mode and dynamic TLS with explicit extended API grants."""
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

APIS = ('AreFileApisANSI', 'SetFileApisToANSI', 'SetFileApisToOEM', 'TlsAlloc',
        'TlsFree', 'TlsGetValue', 'TlsSetValue', 'GetLastError', 'SetLastError')
LOW_MASK = 0xf0000018
HIGH_MASK = 7
EXPECTED_CALLS = dict(AreFileApisANSI=3, SetFileApisToANSI=2, SetFileApisToOEM=1,
                      TlsAlloc=3, TlsFree=3, TlsGetValue=4, TlsSetValue=2,
                      GetLastError=2, SetLastError=1)


def startup_fixture():
    code = bytearray(b'\x48\x83\xec\x28');branches = []
    def emit(raw):code.extend(raw)
    def rel(op, rva):emit(op+struct.pack('<i', rva-(0x1000+len(code)+len(op)+4)))
    def call(name):rel(b'\xff\x15', 0x2280+APIS.index(name)*8)
    def fail(condition):
        branches.append(len(code));emit(b'\x0f'+bytes([condition])+bytes(4))
    def check_bool(want):emit(b'\x85\xc0');fail(0x84 if want else 0x85)
    def load_index(rva):rel(b'\x8b\x0d', rva)
    def alloc(rva):
        call('TlsAlloc');emit(b'\x83\xf8\xff');fail(0x84);rel(b'\x89\x05', rva)
    def get_zero(rva):
        load_index(rva);call('TlsGetValue');emit(b'\x48\x85\xc0');fail(0x85)
        call('GetLastError');emit(b'\x85\xc0');fail(0x85)
    call('SetFileApisToANSI');call('AreFileApisANSI');check_bool(True)
    call('SetFileApisToOEM');call('AreFileApisANSI');check_bool(False)
    call('SetFileApisToANSI');call('AreFileApisANSI');check_bool(True)
    alloc(0x2c00);alloc(0x2c04)
    rel(b'\x3b\x05', 0x2c00);fail(0x84)
    emit(b'\xb9'+struct.pack('<I', 777));call('SetLastError');get_zero(0x2c00)
    for rva, value in ((0x2c00, 0xfedcba9876543210), (0x2c04, 0x123456789abcdef0)):
        load_index(rva);emit(b'\x48\xba'+struct.pack('<Q', value));call('TlsSetValue');check_bool(True)
    for rva, value in ((0x2c00, 0xfedcba9876543210), (0x2c04, 0x123456789abcdef0)):
        load_index(rva);call('TlsGetValue');emit(b'\x48\xba'+struct.pack('<Q', value))
        emit(b'\x48\x39\xd0');fail(0x85)
    load_index(0x2c00);call('TlsFree');check_bool(True)
    alloc(0x2c00);get_zero(0x2c00)
    for rva in (0x2c00, 0x2c04):
        load_index(rva);call('TlsFree');check_bool(True)
    emit(b'\xb8\x29\x00\x00\x00\x48\x83\xc4\x28\xc3')
    failure = len(code);emit(b'\xb8\x7f\x00\x00\x00\x48\x83\xc4\x28\xc3')
    for branch in branches:struct.pack_into('<i', code, branch+2, failure-branch-6)
    return imported_pe_modules(bytes(code), {'KERNEL32.dll': APIS}, payload=bytes(64))


def execute(probe, binary, low=LOW_MASK, high=HIGH_MASK):
    run = subprocess.run([str(probe), str(binary), 'Ryzova.exe', 'RYZOVA_TEST', 'explicit',
                          '3', str(low), '1000', str(high)], capture_output=True, text=True, timeout=10)
    result = json.loads(run.stdout)
    if run.returncode != (0 if result['status'] == 0 else 1):
        raise ValueError('startup probe exit/report mismatch')
    return result


def reference(out):
    if platform.system() != 'Windows' or platform.machine().upper() not in ('AMD64', 'X86_64'):
        raise ValueError('requires Windows AMD64')
    out.mkdir(parents=True, exist_ok=True)
    image = startup_fixture();binary = out/'startup-api.exe';binary.write_bytes(image)
    run = subprocess.run([str(binary.resolve())], capture_output=True, timeout=10, check=False)
    if (run.returncode, run.stdout, run.stderr) != (41, b'', b''):
        raise ValueError(f'Windows startup API mismatch: {run!r}')
    receipt = dict(schema='compact-windows-w7-startup-reference/v1',
                   source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                   sha256=hashlib.sha256(image).hexdigest(), exit_code=41, stdout_hex='', stderr_hex='',
                   platform=platform.platform(), arch=platform.machine().upper())
    (out/'startup-api-reference.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')


def verify_reference(ref):
    image = (ref/'startup-api.exe').read_bytes()
    receipt = json.loads((ref/'startup-api-reference.json').read_text(encoding='utf-8'))
    expected = dict(schema='compact-windows-w7-startup-reference/v1',
                    source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    sha256=hashlib.sha256(image).hexdigest(), exit_code=41, stdout_hex='', stderr_hex='')
    if (image != startup_fixture() or any(receipt.get(k) != v for k, v in expected.items()) or
            receipt.get('arch') not in ('AMD64', 'X86_64') or
            not str(receipt.get('platform', '')).startswith('Windows-')):
        raise ValueError('startup reference bytes/provenance mismatch')
    return receipt


def audit(ref, out):
    receipt = verify_reference(ref)
    with tempfile.TemporaryDirectory() as directory:
        probe = build(Path(directory)/'probe')
        result = execute(probe, ref/'startup-api.exe')
        if (result.get('status'), result.get('exit_code'), result.get('exited'), result.get('stdout_hex'),
                result.get('stderr_hex')) != (0, 41, True, '', ''):
            raise ValueError(f'startup execution mismatch: {result}')
        if {k: v for k, v in result['api_calls'].items() if v} != EXPECTED_CALLS:
            raise ValueError('startup API call counts differ')
        for low, high in ((LOW_MASK, 0), ((1<<28)-1, HIGH_MASK)):
            denied = execute(probe, ref/'startup-api.exe', low, high)
            if denied != dict(status=10, executed=False, allocation_bytes=0):
                raise ValueError('startup grant denial occurred after allocation/execution')
    out.mkdir(parents=True, exist_ok=True)
    report = dict(schema='compact-windows-w7-startup-comparison/v1', reference=receipt, execution=result,
                  reference_match=True, jq_execution_verified=False, native_kernel_qualified=False)
    (out/'startup-api-comparison.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('reference', 'audit'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    if args.mode == 'reference':reference(args.out)
    elif args.reference is None:parser.error('audit requires --reference')
    else:audit(args.reference, args.out)
