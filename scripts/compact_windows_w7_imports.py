# SPDX-License-Identifier: GPL-3.0-only
"""Exact UCRT API-set imports using existing checked guest implementations."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

from compact_windows_w2 import ROOT, PREFERRED, pe

MODULES = (
    ('KERNEL32.dll', ('SetLastError', 'GetLastError')),
    ('api-ms-win-crt-heap-l1-1-0.dll', ('malloc', 'calloc', 'realloc', 'free')),
    ('api-ms-win-crt-private-l1-1-0.dll', ('memcpy', 'memmove', 'memcmp')),
    ('api-ms-win-crt-string-l1-1-0.dll', ('memset', 'strlen', 'strcmp', 'strncmp')),
    ('api-ms-win-crt-runtime-l1-1-0.dll', ('_errno',)),
    ('ucrtbase.dll', ('wcslen',)),
)
EXPECTED_CALLS = {name: 2 if name in ('free', '_errno') else 1 for _, names in MODULES for name in names}


def import_fixture(modules=MODULES):
    data = bytearray(4096)
    struct.pack_into('<Q', data, 0, PREFERRED+0x2000)
    data[0x80:0x87] = b'Ryzova\0'
    data[0x90:0x9e] = 'Ryzova\0'.encode('utf-16le')
    lookup = 0x2200
    iat = lookup+sum((len(names)+1)*8 for _, names in modules)
    first_iat = iat
    name_at = 0x2400
    imports = {}
    for index, (module, names) in enumerate(modules):
        module_at = name_at
        raw = module.encode('ascii')+b'\0'
        data[name_at-0x2000:name_at-0x2000+len(raw)] = raw
        name_at += len(raw)+(len(raw)&1)
        struct.pack_into('<IIIII', data, 0x100+index*20, lookup, 0, 0, module_at, iat)
        for name in names:
            hint = name_at
            raw = b'\0\0'+name.encode('ascii')+b'\0'
            data[hint-0x2000:hint-0x2000+len(raw)] = raw
            name_at += len(raw)+(len(raw)&1)
            struct.pack_into('<Q', data, lookup-0x2000, hint)
            struct.pack_into('<Q', data, iat-0x2000, hint)
            imports[name] = iat
            lookup += 8;iat += 8
        lookup += 8;iat += 8
    if name_at > 0x2f00 or 0x2100+(len(modules)+1)*20 > 0x2200:
        raise ValueError('fixture import layout')
    code = bytearray(b'\x48\x83\xec\x28')
    failures = []

    def emit(raw):code.extend(raw)
    def imm(reg, value):
        emit({'cx': b'\xb9', 'dx': b'\xba', 'r8': b'\x41\xb8'}[reg]+struct.pack('<I', value))
    def relative(op, target):
        emit(op+struct.pack('<i', target-(0x1000+len(code)+len(op)+4)))
    def lea(reg, target):relative({'cx': b'\x48\x8d\x0d', 'dx': b'\x48\x8d\x15'}[reg], target)
    def call(name):relative(b'\xff\x15', imports[name])
    def fail_if(op):
        failures.append(len(code));emit(b'\x0f'+bytes([op])+bytes(4))
    def pointer():
        emit(b'\x48\x85\xc0');fail_if(0x84)
        relative(b'\x48\x89\x05', 0x2008)

    imm('cx', 32);call('malloc');pointer()
    emit(b'\x48\x89\xc1');call('free')
    imm('cx', 4);imm('dx', 8);call('calloc');pointer()
    emit(b'\x83\x38\x00');fail_if(0x85)
    emit(b'\x48\x89\xc1');imm('dx', 64);call('realloc');pointer()
    emit(b'\x48\x89\xc1');imm('dx', 65);imm('r8', 16);call('memset')
    lea('cx', 0x2040);relative(b'\x48\x8b\x15', 0x2008);imm('r8', 16);call('memcpy')
    lea('cx', 0x2041);lea('dx', 0x2040);imm('r8', 15);call('memmove')
    lea('cx', 0x2040);relative(b'\x48\x8b\x15', 0x2008);imm('r8', 16);call('memcmp')
    emit(b'\x85\xc0');fail_if(0x85)
    relative(b'\x48\x8b\x0d', 0x2008);call('free')
    lea('cx', 0x2080);call('strlen');emit(b'\x48\x83\xf8\x06');fail_if(0x85)
    lea('cx', 0x2080);lea('dx', 0x2080);call('strcmp');emit(b'\x85\xc0');fail_if(0x85)
    lea('cx', 0x2080);lea('dx', 0x2080);imm('r8', 6);call('strncmp');emit(b'\x85\xc0');fail_if(0x85)
    lea('cx', 0x2090);call('wcslen');emit(b'\x48\x83\xf8\x06');fail_if(0x85)
    call('_errno');emit(b'\x48\x85\xc0');fail_if(0x84);emit(b'\xc7\x00\x2b\x00\x00\x00')
    call('_errno');emit(b'\x83\x38\x2b');fail_if(0x85)
    imm('cx', 1234);call('SetLastError');call('GetLastError')
    emit(b'\x3d'+struct.pack('<I', 1234));fail_if(0x85)
    emit(b'\xb8\x25\x00\x00\x00\x48\x83\xc4\x28\xc3')
    failure = len(code)
    emit(b'\xb8\x7f\x00\x00\x00\x48\x83\xc4\x28\xc3')
    for branch in failures:
        struct.pack_into('<i', code, branch+2, failure-(branch+6))
    image = bytearray(pe(bytes(code), bytes(data), [(0x2000, 10)]))
    # This directory intentionally spans descriptors plus their names/thunks.
    struct.pack_into('<II', image, 0x98+112+8, 0x2100, 0xe00)
    struct.pack_into('<II', image, 0x98+112+12*8, first_iat, iat-first_iat)
    return bytes(image)


def reference(out):
    if platform.system() != 'Windows' or platform.machine().upper() not in ('AMD64', 'X86_64'):
        raise ValueError('requires Windows AMD64')
    out.mkdir(parents=True, exist_ok=True)
    image = import_fixture();binary = out/'api-set.exe';binary.write_bytes(image)
    run = subprocess.run([str(binary.resolve())], capture_output=True, timeout=10, check=False)
    if (run.returncode, run.stdout, run.stderr) != (37, b'', b''):
        raise ValueError(f'Windows API-set reference mismatch: {run!r}')
    receipt = dict(schema='compact-windows-w7-imports-reference/v1',
                   source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                   sha256=hashlib.sha256(image).hexdigest(), exit_code=37,
                   stdout_hex='', stderr_hex='', platform=platform.platform(), arch=platform.machine().upper())
    (out/'api-set-reference.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')


def verify_reference(ref):
    image = (ref/'api-set.exe').read_bytes()
    receipt = json.loads((ref/'api-set-reference.json').read_text(encoding='utf-8'))
    expected = dict(schema='compact-windows-w7-imports-reference/v1',
                    source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    sha256=hashlib.sha256(image).hexdigest(), exit_code=37, stdout_hex='', stderr_hex='')
    if (image != import_fixture() or any(receipt.get(k) != v for k, v in expected.items()) or
            receipt.get('arch') not in ('AMD64', 'X86_64') or
            not str(receipt.get('platform', '')).startswith('Windows-')):
        raise ValueError('API-set reference bytes/provenance mismatch')
    return receipt


def audit(ref, out):
    from compact_windows_w5 import build, execute
    receipt = verify_reference(ref);results = []
    with tempfile.TemporaryDirectory() as directory:
        probe = build(Path(directory)/'probe')
        result = execute(probe, ref/'api-set.exe')
        if (result.get('status'), result.get('exit_code'), result.get('exited'),
                result.get('stdout_hex'), result.get('stderr_hex')) != (0, 37, True, '', ''):
            raise ValueError(f'API-set execution mismatch: {result}')
        if {k: v for k, v in result.get('api_calls', {}).items() if v} != EXPECTED_CALLS:
            raise ValueError('API-set thunk call counts differ')
        results.append(result)
    out.mkdir(parents=True, exist_ok=True)
    report = dict(schema='compact-windows-w7-imports-comparison/v1', reference=receipt,
                  executions=results, reference_match=True, jq_execution_verified=False,
                  native_kernel_qualified=False)
    (out/'api-set-comparison.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('reference', 'audit'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    if args.mode == 'reference':reference(args.out)
    elif args.reference is None:parser.error('audit requires --reference')
    else:audit(args.reference, args.out)
