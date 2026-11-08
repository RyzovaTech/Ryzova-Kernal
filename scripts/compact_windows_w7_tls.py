# SPDX-License-Identifier: GPL-3.0-only
"""Reproducible PE with static TLS and ordered process-attach callbacks."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess

from compact_windows_w2 import pe, PREFERRED, build, execute
import tempfile

TLS_DIRECTORY = 0x3040
TLS_CALLBACK_ARRAY = 0x3070
TLS_INDEX = 0x2020
TLS_MARKER = 0x2024
TLS_READ = bytes.fromhex('65 48 8b 04 25 58 00 00 00 48 8b 00')


def tls_fixture(callbacks=2, entry=None, callback_code=None, zero=16):
    if not 0 <= callbacks <= 9:
        raise ValueError('fixture callback limit')
    code = bytearray((entry if entry is not None else TLS_READ+b'\x8b\x00\xc3').ljust(256, b'\x90'))
    relocations = [(TLS_DIRECTORY+i, 10) for i in (0, 8, 16, 24)]
    targets = []
    for index in range(callbacks):
        rva = 0x1100+index*128
        targets.append(PREFERRED+rva)
        # Ignore thread/detach notifications; this fixture tests process attach.
        body = bytearray(b'\x83\xfa\x01\x74\x01\xc3')
        body += b'\x48\xb8'+struct.pack('<Q', PREFERRED)
        if callback_code is None:
            relocations.append((rva+8, 10))
        branches = []
        for check in (b'\x48\x39\xc1', b'\x4d\x85\xc0'):
            body += check
            branches.append(len(body));body += b'\x75\x00'
        # The prior callback must have completed before this one begins.
        body += b'\x83\x3d'+struct.pack('<i', TLS_MARKER-(rva+len(body)+7))+bytes([index])
        branches.append(len(body));body += b'\x75\x00'
        body += b'\xff\x05'+struct.pack('<i', TLS_MARKER-(rva+len(body)+6))
        body += TLS_READ+b'\x83\x00\x01\xc3'
        trap = len(body);body += b'\x0f\x0b'
        for branch in branches:
            body[branch+1] = trap-branch-2
        body = callback_code if callback_code is not None else bytes(body)
        if len(body) > 128:
            raise ValueError('callback fixture extent')
        code += body.ljust(128, b'\x90')
        relocations.append((TLS_CALLBACK_ARRAY+index*8, 10))
    data = bytearray(64)
    struct.pack_into('<II', data, 0, 7, 0x13579bdf)
    struct.pack_into('<I', data, 32, 0xaaaaaaaa)
    image = bytearray(pe(bytes(code), bytes(data), relocations))
    third = 0x188+2*40
    raw = struct.unpack_from('<I', image, third+20)[0]
    image[third:third+8] = b'.rdata\x00\x00'
    struct.pack_into('<I', image, third+8, 256)
    struct.pack_into('<I', image, third+36, 0x40000040)
    struct.pack_into('<QQQQII', image, raw+64,
                     PREFERRED+0x2000, PREFERRED+0x2008, PREFERRED+TLS_INDEX,
                     PREFERRED+TLS_CALLBACK_ARRAY, zero, 0x00500000)
    for index, target in enumerate([*targets, 0]):
        struct.pack_into('<Q', image, raw+112+8*index, target)
    struct.pack_into('<II', image, 0x98+112+9*8, TLS_DIRECTORY, 40)
    return bytes(image)


def reference(out):
    if platform.system() != 'Windows' or platform.machine().upper() not in ('AMD64', 'X86_64'):
        raise ValueError('requires Windows AMD64')
    out.mkdir(parents=True, exist_ok=True)
    image = tls_fixture()
    binary = out/'tls.exe';binary.write_bytes(image)
    run = subprocess.run([str(binary.resolve())], capture_output=True, timeout=10, check=False)
    if (run.returncode, run.stdout, run.stderr) != (9, b'', b''):
        raise ValueError(f'Windows TLS reference mismatch: {run!r}')
    root = Path(__file__).resolve().parents[1]
    receipt = dict(schema='compact-windows-w7-tls-reference/v1',
                   source_commit=subprocess.check_output(['git','rev-parse','HEAD'], cwd=root, text=True).strip(),
                   sha256=hashlib.sha256(image).hexdigest(), exit_code=9,
                   stdout_hex='', stderr_hex='', platform=platform.platform(),
                   arch=platform.machine().upper())
    (out/'tls-reference.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')


def verify_reference(ref):
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git','rev-parse','HEAD'], cwd=root, text=True).strip()
    image = (ref/'tls.exe').read_bytes()
    receipt = json.loads((ref/'tls-reference.json').read_text(encoding='utf-8'))
    expected = dict(schema='compact-windows-w7-tls-reference/v1', source_commit=commit,
                    sha256=hashlib.sha256(image).hexdigest(), exit_code=9, stdout_hex='', stderr_hex='')
    if (image != tls_fixture() or any(receipt.get(k) != v for k, v in expected.items()) or
            receipt.get('arch') not in ('AMD64', 'X86_64') or
            not str(receipt.get('platform', '')).startswith('Windows-')):
        raise ValueError('TLS reference bytes/provenance mismatch')
    return receipt


def audit(ref, out):
    receipt = verify_reference(ref)
    results = []
    with tempfile.TemporaryDirectory() as directory:
        probe = build(Path(directory)/'probe', sanitize=True)
        for base in (PREFERRED, PREFERRED+0x40000000, PREFERRED-0x40000000):
            result = execute(probe, ref/'tls.exe', base)
            if (result.get('status'), result.get('exit_code'), result.get('exited'),
                    result.get('nonvolatile_preserved')) != (0, 9, True, True):
                raise ValueError(f'TLS execution mismatch: {result}')
            results.append(result)
    out.mkdir(parents=True, exist_ok=True)
    report = dict(schema='compact-windows-w7-tls-comparison/v1', reference=receipt,
                  executions=results, reference_match=True,
                  evidence_scope='hosted Ryzova interpreter; process attach for one image and initial thread',
                  jq_execution_verified=False, native_kernel_qualified=False)
    (out/'tls-comparison.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('reference', 'audit'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    if args.mode == 'reference':
        reference(args.out)
    elif args.reference is None:
        parser.error('audit requires --reference')
    else:
        audit(args.reference, args.out)
