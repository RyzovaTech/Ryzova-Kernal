# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the M8 loader and startup boundary with exact macOS reference bytes."""
import argparse
import ctypes as C
import json
import random
from pathlib import Path
import struct

from compact_c2_file_contract import PARENT_ESCAPE
from compact_macos_m8_jq import INPUT, TARGETS, save_json, sha256, source_head, verified_image


CAP = 1024 * 1024
STACK = 65536
HEAP = 4*1024*1024
ARENA = 4*CAP+STACK+HEAP+8192
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
    )] + [('names', C.c_uint * 256), ('segments', Segment * 5), ('system_import', C.c_ubyte * 256)]


class Stop(C.Structure):
    _fields_ = [(name, C.c_ulonglong) for name in ('pc', 'last_pc', 'arg0', 'arg1', 'arg2', 'arg3', 'link')
                ] + [(name, C.c_uint) for name in ('steps', 'name', 'locale_calls', 'alloc_calls', 'exit_code', 'stdout_bytes', 'stderr_bytes',
                                           'file_opens', 'file_reads')] + [
                    ('stdout_data', C.c_ubyte * 256), ('stderr_data', C.c_ubyte * 256)]


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
    if stop.exit_code != expected['exit_code'] or stdout.hex() != expected['stdout_hex'] or bytes(
            stop.stderr_data[:stop.stderr_bytes]).hex() != expected['stderr_hex']:
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


def check_query(lib, arch, image, expected):
    arena = C.create_string_buffer(ARENA)
    argv = [b'jq', *(arg.encode('ascii') for arg in expected['argv'])]
    arguments = (C.c_char_p*len(argv))(*argv)

    def run(payload, wanted):
        source = C.create_string_buffer(payload)
        stop = Stop()
        status = lib.mac8_run(image, len(image), arena, len(arena), GUARD,
                              len(arguments), arguments, 16777216, source, len(payload), C.byref(stop))
        if status != 2 or stop.exit_code != expected['exit_code']:
            name = image[stop.name:].split(b'\0', 1)[0] if stop.name else b''
            raise ValueError(f'{arch}: query stopped at {stop.last_pc:#x}, {name!r}, after {stop.steps} steps')
        stdout = bytes(stop.stdout_data[:stop.stdout_bytes])
        stderr = bytes(stop.stderr_data[:stop.stderr_bytes])
        if (stdout, stderr, stop.file_opens, stop.file_reads, source.raw) != (
                wanted, bytes.fromhex(expected['stderr_hex']), 1, len(payload), payload+b'\0'):
            raise ValueError(f'{arch}: query output or read-only input grant differs')
        return dict(steps=stop.steps, stdout_hex=stdout.hex(), stderr_hex=stderr.hex(),
                    exit_code=stop.exit_code, file_opens=1, bytes_read=len(payload),
                    input_sha256=sha256(payload), input_unchanged=True, reference_match=True)

    report = run(INPUT, bytes.fromhex(expected['stdout_hex']))
    run(b'{"items":[7,8]}\n', b'{"count":2,"sum":15}\n')
    denied = Stop()
    status = lib.mac8_run(image, len(image), arena, len(arena), GUARD,
                          len(arguments), arguments, 16777216, None, 0, C.byref(denied))
    name = expected['argv'][-1]
    stderr = f'jq: error: Could not open file {name}: No such file or directory\n'.encode()
    if (status, denied.exit_code, denied.file_opens, denied.file_reads, denied.stdout_bytes,
            bytes(denied.stderr_data[:denied.stderr_bytes])) != (2, 2, 0, 0, 0, stderr):
        raise ValueError(f'{arch}: unexpected jq result without an input grant')
    report['missing_grant_denied'] = True
    return report


def check_parent_escape(lib, arch, image, expected):
    argv = [b'jq', *(arg.encode('ascii') for arg in expected['argv'][:-1]), PARENT_ESCAPE.encode()]
    arguments = (C.c_char_p*len(argv))(*argv)
    arena = C.create_string_buffer(ARENA)
    payload = C.create_string_buffer(INPUT)
    stop = Stop()
    alias = expected['argv'][-1].encode()
    status = lib.mac9_run(image, len(image), arena, len(arena), GUARD, len(argv), arguments,
                          16777216, alias, payload, len(INPUT), C.byref(stop))
    stderr = f'jq: error: Could not open file {PARENT_ESCAPE}: No such file or directory\n'.encode()
    if (status, stop.exit_code, stop.file_opens, stop.file_reads, stop.stdout_bytes,
            bytes(stop.stderr_data[:stop.stderr_bytes]), payload.raw) != (2, 2, 0, 0, 0, stderr, INPUT+b'\0'):
        raise ValueError(f'{arch}: unexpected parent escape result with read-only grant')
    return dict(exit_code=2, file_opens=0, bytes_read=0, stdout_hex='', stderr_hex=stderr.hex())


def check_launcher(lib, arch, image):
    arena = C.create_string_buffer(ARENA)
    source = C.create_string_buffer(INPUT)
    alias = b'records-01.json'

    def run(name, grant):
        args = (C.c_char_p*4)(b'jq', b'-c', b'.items', name)
        stop = Stop()
        status = lib.mac9_run(image, len(image), arena, len(arena), GUARD,
                              len(args), args, 16777216, grant, source, len(INPUT), C.byref(stop))
        return status, stop

    status, stop = run(alias, alias)
    stdout = bytes(stop.stdout_data[:stop.stdout_bytes])
    if (status, stop.exit_code, stdout, stop.stderr_bytes, stop.file_opens, stop.file_reads) != (
            2, 0, b'[2,3,5]\n', 0, 1, len(INPUT)) or source.raw != INPUT+b'\0':
        raise ValueError(f'{arch}: caller argv or selected file alias differs at {stop.last_pc:#x}')
    for name in (b'input.json', b'../'+alias, b'/'+alias):
        status, denied = run(name, alias)
        if denied.file_opens or denied.file_reads or denied.stdout_bytes or (status==2 and not denied.exit_code):
            raise ValueError(f'{arch}: grant escaped via {name!r}')
    for bad in (b'', b'.', b'..', b'../escape', b'a/b', b'a\\b', b'a:b', b'a b', b'a'*64):
        status, denied = run(alias, bad)
        if status or denied.steps or lib.mac9_grant_name(bad):
            raise ValueError(f'{arch}: invalid guest basename admitted: {bad!r}')
    return dict(stdout_hex=stdout.hex(), guest_alias=alias.decode(), input_unchanged=True,
                exact_alias_enforced=True)


def check_float(lib):
    word = C.c_ulonglong
    lib.mac8_fma.argtypes = [word, word, word, C.POINTER(word)]
    lib.mac8_fp_div.argtypes = [word, word, C.POINTER(word)]
    lib.mac8_fp_from_int.argtypes = [word, C.c_uint, C.c_int]
    lib.mac8_fp_from_int.restype = word
    lib.mac8_fp_to_int.argtypes = [word, C.c_uint]
    lib.mac8_fp_to_int.restype = word
    libc_fma = C.CDLL('libm.so.6').fma
    libc_fma.argtypes = [C.c_double]*3
    libc_fma.restype = C.c_double
    bits = lambda value: struct.unpack('<Q', struct.pack('<d', value))[0]
    rng = random.Random(91)
    cases = [(1.0+2**-27, 1.0-2**-27, -1.0), (1.0, 1.0, 2**-53), (-0.0, 1.0, -0.0)]
    cases.extend(tuple(rng.uniform(-10**6, 10**6) for _ in range(3)) for _ in range(300))
    for case in cases:
        out = word()
        if lib.mac8_fma(*(bits(x) for x in case), C.byref(out)) != 1 or out.value != bits(libc_fma(*case)):
            raise ValueError(f'ARM64 fused arithmetic differs for {case}')

    for _ in range(300):
        a, b = (rng.uniform(-10**6, 10**6) for _ in range(2))
        out = word()
        if lib.mac8_fp_div(bits(a), bits(b), C.byref(out)) != 1 or out.value != bits(a/b):
            raise ValueError('ARM64 binary64 division differs')
        value = rng.getrandbits(64)
        signed = value if value < 2**63 else value-2**64
        for is_signed, number in ((0, value), (1, signed)):
            if lib.mac8_fp_from_int(value, 64, is_signed) != bits(float(number)):
                raise ValueError('ARM64 integer-to-float conversion differs')
        if lib.mac8_fp_to_int(bits(a), 64) != int(a) % 2**64:
            raise ValueError('ARM64 float-to-integer conversion differs')


def check_heap(lib):
    class Heap(C.Structure):
        _fields_ = [('count', C.c_uint), ('blocks', C.c_uint * 98304)]

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
    lib.mac8_run.argtypes = [C.c_void_p, C.c_uint, C.c_void_p, C.c_uint, C.c_ulonglong,
                            C.c_uint, C.POINTER(C.c_char_p), C.c_uint, C.c_void_p, C.c_uint,
                            C.POINTER(Stop)]
    lib.mac9_grant_name.argtypes = [C.c_char_p]
    lib.mac9_run.argtypes = lib.mac8_run.argtypes[:-3]+[C.c_char_p]+lib.mac8_run.argtypes[-3:]
    check_heap(lib)
    check_float(lib)
    report = {}
    for arch, (name, _, _, _, _) in TARGETS.items():
        reference = args.references/f'macos-m8-jq-{arch}'
        image = verified_image(arch, (reference/name).read_bytes())
        cases = json.loads((reference/'reference.json').read_text())['cases']
        report[arch] = map_and_check(lib, arch, image)
        report[arch]['startup'] = check_start(lib, arch, image)
        report[arch]['version'] = check_version(lib, arch, image, cases['version'])
        report[arch]['query'] = check_query(lib, arch, image, cases['query'])
        report[arch]['parent_escape'] = check_parent_escape(lib, arch, image, cases['query'])
        report[arch]['launcher'] = check_launcher(lib, arch, image)
        print(f'{arch}: mapped {report[arch]["mapped_bytes"]} bytes, checked '
              f'{len(report[arch]["rejected"])} malformed images and traced '
              f'{report[arch]["startup"]["steps"]} instructions to the first import. Version and query match.')
    save_json(args.output, dict(schema='compact-macos-m8-hosted-jq/v1',
                               source_commit=source_head(), architectures=report))


if __name__ == '__main__':
    main()
