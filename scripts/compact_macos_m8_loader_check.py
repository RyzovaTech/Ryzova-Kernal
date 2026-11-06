# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the M8 loader and startup boundary with exact macOS reference bytes."""
import argparse
import ctypes as C
import json
from pathlib import Path
import struct

from compact_macos_m8_jq import TARGETS, save_json, sha256, source_head, verified_image


CAP = 1024 * 1024
STACK = 65536
HEAP = 512*1024
ARENA = CAP+STACK+HEAP+8192
GUARD = 0x1234567800000000
BASE = 0x200000
UNRESOLVED = 0x10000
R, W, X = 1, 2, 4
EXPECTED = {
    'x86_64': (4096, 2144, 856064, 136, 1221, 6),
    'arm64': (16384, 14664, 851968, 135, 1232, 3),
}
FIRST_IMPORT = {
    'x86_64': (15, 0x6f227, 0xbe4b8),
    'arm64': (18, 0x66a88, 0xb4810),
}


class Segment(C.Structure):
    _fields_ = [(name, C.c_uint) for name in ('offset', 'bytes', 'file_bytes', 'protection')]


class Image(C.Structure):
    _fields_ = [(name, C.c_uint) for name in (
        'cpu', 'page', 'entry', 'mapped_bytes', 'imports', 'binds',
        'rebases', 'fixup_pages', 'bss', 'bss_bytes',
    )] + [('names', C.c_uint * 256), ('segments', Segment * 5)]


class Stop(C.Structure):
    _fields_ = [(name, C.c_ulonglong) for name in ('pc', 'last_pc', 'arg0', 'arg1')
                ] + [(name, C.c_uint) for name in ('steps', 'name', 'locale_calls', 'alloc_calls', 'exit_code', 'stdout_bytes')] + [
                    ('stdout_data', C.c_ubyte * 256)]


def commands(image):
    count = struct.unpack_from('<I', image, 16)[0]
    offset = 32
    for _ in range(count):
        kind, size = struct.unpack_from('<II', image, offset)
        yield kind, offset
        offset += size


def changed(image, offset, fmt, value):
    copy = bytearray(image)
    struct.pack_into('<'+fmt, copy, offset, value)
    return bytes(copy)


def map_and_check(lib, arch, image):
    plan = Image()
    arena = C.create_string_buffer(CAP)
    if lib.mac8_load(image, len(image), arena, CAP, C.byref(plan)) != 1:
        raise ValueError(f'{arch}: bounded image map rejected')
    actual = (plan.page, plan.entry, plan.mapped_bytes, plan.imports, plan.rebases, plan.fixup_pages)
    if actual != EXPECTED[arch] or plan.binds != plan.imports:
        raise ValueError(f'{arch}: unexpected mapped layout {actual}')
    if [seg.protection for seg in plan.segments] != [0, R|X, R, R|W, R]:
        raise ValueError(f'{arch}: unexpected permissions')
    if arena[:plan.segments[1].file_bytes] != image[:plan.segments[1].file_bytes]:
        raise ValueError(f'{arch}: text bytes changed')
    if arena[plan.bss:plan.bss+plan.bss_bytes] != bytes(plan.bss_bytes):
        raise ValueError(f'{arch}: bss was not zeroed')

    access = lambda at, n, rights: lib.mac8_access(C.byref(plan), at, n, rights)
    data = BASE+plan.segments[3].offset
    const = BASE+plan.segments[2].offset
    if (not access(BASE+plan.entry, 4, R|X) or not access(data, 8, W)
            or access(const, 8, W) or access(data, 8, X) or access(BASE+plan.entry, 1, W)
            or access(const-4, 8, R) or access(UNRESOLVED, 1, X)
            or access(BASE+plan.mapped_bytes, 1, R) or access(0, 1, R)):
        raise ValueError(f'{arch}: guest segment access gate mismatch')

    table = dict((kind, at) for kind, at in commands(image) if kind != 0x19)
    fixoff = struct.unpack_from('<I', image, table[0x80000034]+8)[0]
    startoff = fixoff+struct.unpack_from('<I', image, fixoff+4)[0]
    chainoff = startoff+struct.unpack_from('<I', image, startoff+12)[0]
    first_slot = plan.segments[2].offset+struct.unpack_from('<H', image, chainoff+22)[0]
    bind_slot = first_slot
    for _ in range(plan.page//8):
        first_bind = struct.unpack_from('<Q', image, bind_slot)[0]
        if first_bind>>63:
            break
        next_offset = ((first_bind>>51)&4095)*4
        if not next_offset:
            raise ValueError(f'{arch}: expected an import in the first data-const chain')
        bind_slot += next_offset
    else:
        raise ValueError(f'{arch}: no first-page bind')
    thunk = struct.unpack_from('<Q', arena, bind_slot)[0]
    if thunk != UNRESOLVED+16*(first_bind&0xffffff):
        raise ValueError(f'{arch}: unresolved bind did not map to an inert guest token')
    text, data_cmd = [at for cmd, at in commands(image) if cmd==0x19][1::2]
    negative = {
        'truncated': (image[:-1], CAP),
        'arena-limit': (image, plan.mapped_bytes-1),
        'writable-text': (changed(image, text+60, 'I', 7), CAP),
        'data-alias': (changed(image, data_cmd+24, 'Q', 0x100000000), CAP),
        'non-text-entry': (changed(image, table[0x80000028]+8, 'Q', plan.segments[3].offset), CAP),
        'bad-fixup-range': (changed(image, table[0x80000034]+8, 'I', len(image)), CAP),
        'wrong-fixup-format': (changed(image, chainoff+6, 'H', 2), CAP),
        'cross-page-fixup': (changed(image, chainoff+22, 'H', plan.page-4), CAP),
        'bind-ordinal': (changed(image, bind_slot, 'Q', (first_bind&~0xffffff)|0xffffff), CAP),
        'short-hop': (changed(image, bind_slot, 'Q', (first_bind&~(4095<<51))|(1<<51)), CAP),
        'bad-rebase': (changed(image, first_slot, 'Q', (1<<36)-1), CAP),
    }
    untouched = b'\xa5'*CAP
    rejected = C.create_string_buffer(untouched, CAP)
    poison = Image()
    C.memset(C.byref(poison), 0xa5, C.sizeof(poison))
    for name, (candidate, capacity) in negative.items():
        if (lib.mac8_load(candidate, len(candidate), rejected, capacity, C.byref(poison)) != 0
                or rejected.raw != untouched or bytes(poison) != b'\xa5'*C.sizeof(poison)):
            raise ValueError(f'{arch}: bad image mutated state or admitted: {name}')

    return dict(sha256=sha256(image), page_bytes=plan.page, entry=plan.entry,
                mapped_bytes=plan.mapped_bytes, binds=plan.binds, rebases=plan.rebases,
                fixup_pages=plan.fixup_pages, bss_bytes=plan.bss_bytes,
                rejected=sorted(negative), workload_execution_verified=False)


def check_start(lib, arch, image):
    arena = C.create_string_buffer(CAP+STACK)
    stop = Stop()
    if lib.mac8_start(image, len(image), arena, len(arena), 0, C.byref(stop)) != 1:
        raise ValueError(f'{arch}: startup stopped at {stop.last_pc:#x} after {stop.steps} steps')
    name = image[stop.name:].split(b'\0', 1)[0]
    actual = stop.steps, stop.last_pc-BASE, stop.arg1-BASE
    if (actual != FIRST_IMPORT[arch] or name != b'_setlocale' or stop.arg0 != 0
            or arena[stop.arg1-BASE:stop.arg1-BASE+1] != b'\0'):
        raise ValueError(f'{arch}: unexpected first import {name!r}, {actual}')

    # A valid mapping with an invalid entry opcode must stop at the entry.
    entry = EXPECTED[arch][1]
    unsupported = b'\x0f\x0b' if arch == 'x86_64' else bytes(4)
    candidate = image[:entry]+unsupported+image[entry+len(unsupported):]
    rejected = Stop()
    if (lib.mac8_start(candidate, len(candidate), arena, len(arena), 0, C.byref(rejected)) != 0
            or rejected.steps != 0 or rejected.last_pc != BASE+entry or rejected.pc):
        raise ValueError(f'{arch}: invalid entry opcode did not stop startup')
    return dict(steps=stop.steps, last_instruction_rva=stop.last_pc-BASE,
                unresolved_import=name.decode('ascii'), workload_execution_verified=False)


def check_version(lib, arch, image, expected):
    def run(binary):
        arena = C.create_string_buffer(ARENA)
        stop = Stop()
        status = lib.mac8_start(binary, len(binary), arena, len(arena), GUARD, C.byref(stop))
        if status != 2 or stop.locale_calls != 1 or stop.alloc_calls != 5:
            raise ValueError(f'{arch}: version stopped at {stop.last_pc:#x} after {stop.steps} steps')
        return stop, bytes(stop.stdout_data[:stop.stdout_bytes])

    stop, stdout = run(image)
    if stop.exit_code != expected['exit_code'] or stdout.hex() != expected['stdout_hex'] or expected['stderr_hex']:
        raise ValueError(f'{arch}: version differs from the macOS reference')

    # Changing guest format bytes changes guest output through the same ABI.
    original = b'jq-%s\n\0'
    if image.count(original) != 1:
        raise ValueError(f'{arch}: expected exactly one jq version format string')
    changed_stop, changed_stdout = run(image.replace(original, b'JQ-%s\n\0'))
    if changed_stop.exit_code or changed_stdout != b'JQ-1.8.1\n':
        raise ValueError(f'{arch}: stdout did not follow guest format bytes')
    return dict(steps=stop.steps, stdout_hex=stdout.hex(), stderr_hex='', exit_code=stop.exit_code,
                locale_calls=stop.locale_calls, allocations=stop.alloc_calls, reference_match=True)


def check_heap(lib):
    class Heap(C.Structure):
        _fields_ = [('count', C.c_uint), ('blocks', C.c_uint * 1024)]

    lib.mac8_alloc.argtypes = [C.POINTER(Heap), C.c_ulonglong]
    lib.mac8_alloc.restype = C.c_uint
    lib.mac8_free.argtypes = [C.POINTER(Heap), C.c_uint]
    heap = Heap()
    alloc = lambda size: lib.mac8_alloc(C.byref(heap), size)
    free = lambda offset: lib.mac8_free(C.byref(heap), offset)
    if (alloc(17), alloc(0), alloc(HEAP-48), alloc(1)) != (0, 32, 48, HEAP):
        raise ValueError('heap layout or exhaustion differs')
    if free(16) or not free(0) or free(0) or alloc(32) != 0 or alloc(2**64-1) != HEAP:
        raise ValueError('heap ownership, reuse or overflow gate failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('loader', type=Path)
    parser.add_argument('references', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    lib = C.CDLL(str(args.loader.resolve()))
    lib.mac8_load.argtypes = [C.c_void_p, C.c_uint, C.c_void_p, C.c_uint, C.POINTER(Image)]
    lib.mac8_access.argtypes = [C.POINTER(Image), C.c_ulonglong, C.c_uint, C.c_uint]
    lib.mac8_start.argtypes = [C.c_void_p, C.c_uint, C.c_void_p, C.c_uint, C.c_ulonglong, C.POINTER(Stop)]
    check_heap(lib)
    report = {}
    for arch, (name, _, _, _, _) in TARGETS.items():
        reference = args.references/f'macos-m8-jq-{arch}'
        image = verified_image(arch, (reference/name).read_bytes())
        expected = json.loads((reference/'reference.json').read_text())['cases']['version']
        report[arch] = map_and_check(lib, arch, image)
        report[arch]['startup'] = check_start(lib, arch, image)
        report[arch]['version'] = check_version(lib, arch, image, expected)
        print(f'{arch}: mapped {report[arch]["mapped_bytes"]} bytes, checked '
              f'{len(report[arch]["rejected"])} malformed images and traced '
              f'{report[arch]["startup"]["steps"]} instructions to the first import. Version matches.')
    save_json(args.output, dict(schema='compact-macos-m8-hosted-version/v1',
                               source_commit=source_head(), architectures=report))


if __name__ == '__main__':
    main()
