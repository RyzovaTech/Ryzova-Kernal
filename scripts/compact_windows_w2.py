# SPDX-License-Identifier: AGPL-3.0-only
"""Build portable Windows runtime and reproducible executable PE test images."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PREFERRED = 0x140000000

def pe(code, data=b'', relocations=()):
    """Strict console PE32+, normal 4K/512 alignment; no imported DLLs."""
    count = 1 + bool(data) + bool(relocations)
    headers = ((0x188 + count * 40 + 511) // 512) * 512
    sections = [(b'.text', code, max(1, len(code)), 0x60000020)]
    if data:
        sections.append((b'.data', data, max(len(data), 1024), 0xC0000040))
    if relocations:
        groups = {}
        for target, kind in relocations:
            groups.setdefault(target & ~4095, []).append((kind << 12) | (target & 4095))
        table = bytearray()
        for page, entries in sorted(groups.items()):
            if len(entries) % 2:
                entries.append(0)
            table += struct.pack('<II', page, 8 + 2 * len(entries))
            table += struct.pack('<' + 'H' * len(entries), *entries)
        sections.append((b'.reloc', bytes(table), len(table), 0x42000040))
    blob = bytearray(headers)
    blob[:2] = b'MZ'
    struct.pack_into('<I', blob, 60, 0x80)
    blob[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', blob, 0x84, 0x8664, count, 0, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into('<H', blob, opt, 0x20B)
    struct.pack_into('<I', blob, opt + 16, 0x1000)
    struct.pack_into('<I', blob, opt + 20, 0x1000)
    struct.pack_into('<Q', blob, opt + 24, PREFERRED)
    struct.pack_into('<II', blob, opt + 32, 4096, 512)
    struct.pack_into('<HH', blob, opt + 40, 6, 0)
    struct.pack_into('<HH', blob, opt + 48, 6, 0)
    struct.pack_into('<II', blob, opt + 56, (count + 1) * 4096, headers)
    struct.pack_into('<HH', blob, opt + 68, 3, 0x100)
    struct.pack_into('<QQQQ', blob, opt + 72, 65536, 4096, 65536, 4096)
    struct.pack_into('<I', blob, opt + 108, 16)
    for i, (name, payload, virtual_size, flags) in enumerate(sections):
        raw_size = ((len(payload) + 511) // 512) * 512
        raw = len(blob)
        section = 0x188 + i * 40
        blob[section:section + 8] = name.ljust(8, b'\0')
        struct.pack_into('<IIII', blob, section + 8, virtual_size, (i + 1) * 4096, raw_size, raw)
        struct.pack_into('<I', blob, section + 36, flags)
        blob += payload + bytes(raw_size - len(payload))
        if name == b'.reloc':
            struct.pack_into('<II', blob, opt + 112 + 5 * 8, (i + 1) * 4096, len(payload))
    return bytes(blob)

def fixtures():
    # [data] is a relocated pointer to [data+8], proving DIR64 consumption.
    relocated = pe(b'\x48\x8b\x05' + struct.pack('<i', 0x2000 - 0x1007) + b'\x8b\x00\xc3',
                   struct.pack('<QI', PREFERRED + 0x2008, 0x12345678), [(0x2000, 10)])
    return {'exit32': pe(b'\xb8\x98\xba\xdc\xfe\xc3'),
            'relocated': relocated, 'loop': pe(b'\xeb\xfe'),
            'syscall-denied': pe(b'\x0f\x05'), 'opcode-denied': pe(b'\x0f\x0b')}

def build(output, sanitize=False):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O2']
    if sanitize:
        flags += ['-fsanitize=undefined', '-fno-sanitize-recover=all']
    subprocess.run([os.environ.get('CC', 'cc'), *flags, *[str(ROOT / 'ryzova/compat/windows' / x)
                   for x in ('loader.c', 'cpu.c', 'runtime_probe.c')], '-o', str(output)], check=True)
    return output

def execute(probe, path, base=0, budget=262144):
    run = subprocess.run([str(probe), str(path), str(base), str(budget)], capture_output=True, text=True, timeout=10)
    report = json.loads(run.stdout)
    if run.returncode != (0 if report['status'] == 0 else 1):
        raise ValueError('probe exit and receipt disagree')
    return report

def qualify_reference(probe, image, receipt, output, base=0):
    """Compare actual runtime execution with a source-identified Windows host run."""
    native = json.loads(Path(receipt).read_text(encoding='utf-8-sig'))
    actual_sha = hashlib.sha256(Path(image).read_bytes()).hexdigest()
    source_sha = hashlib.sha256((ROOT / 'tests/fixtures/windows_w2_reference.c').read_bytes()).hexdigest()
    expected_commit = os.environ.get('GITHUB_SHA')
    if (native.get('schema') != 'compact-windows-w2-reference/v1' or
        native.get('executable_sha256') != actual_sha or native.get('source_sha256') != source_sha or
        native.get('native_reference_passed') is not True or native.get('exit_code') != 0x12345678 or
        native.get('architecture') != 'X64' or
        not isinstance(native.get('platform'), str) or not native['platform'].startswith('Microsoft Windows ') or
        native.get('stdout') != '' or native.get('stderr') != '' or
        not expected_commit or native.get('source_commit') != expected_commit):
        raise ValueError('reference provenance/result mismatch')
    result = execute(probe, image, base)
    if (result.get('status') != 0 or result.get('exited') is not True or
        result.get('executed') is not True or result.get('exit_code') != native['exit_code'] or
        result.get('nonvolatile_preserved') is not True):
        raise ValueError(f'Windows/Flex runtime mismatch: {result}')
    result.update(schema='compact-windows-w2-comparison/v1', source_commit=expected_commit,
                  executable_sha256=actual_sha, reference_match=True,
                  evidence_scope='hosted Flex Windows subset interpreter; not native Flex kernel/QEMU')
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(result, indent=2) + '\n')
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/compact-windows/w2')
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    binary = build(args.output / 'runtime-probe', sanitize=True)
    if args.reference:
        print(json.dumps(qualify_reference(binary, args.reference, args.receipt, args.output / 'comparison.json'), indent=2))
    else:
        for name, blob in fixtures().items():
            path = args.output / (name + '.exe')
            path.write_bytes(blob)
            print(name, json.dumps(execute(binary, path, 0x180000000 if name == 'relocated' else 0, 1000)))
