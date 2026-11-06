# SPDX-License-Identifier: GPL-3.0-only
"""Pin the SQLite shell references and measure Compact macOS loader admission."""
import argparse
import ctypes as C
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import struct
import subprocess
from urllib.request import urlopen
import zipfile

from compact_macos_m8_jq import save_json, source_head
from compact_macos_m8_loader_check import BASE, Image, R, W, X, UNRESOLVED, changed, commands

RELEASE = 'https://www.sqlite.org/2026'
VERSION = '3.54.1'
TARGETS = {
    'x86_64': ('x64', '6a65ac5bff00b0b5251239462dffc70e704bcf1a49e603d5af9fb2812556d113', 0x01000007),
    'arm64': ('arm64', 'a3106c6db3b50ec9ef4fde4edfafe7504179e9bfd7e0816a280b29c4d56a2e7b', 0x0100000c),
}
IMAGE_SHA256 = {
    'x86_64': '035e09884838dcf79b5f5edc6ee4de6ece2f7553ba8ca4294922d4760599e92f',
    'arm64': '9a538234fe523a7bda07d526950c53f7054e5c41401510d1af3d7adf9ba2026d',
}
EXPECTED_MAP = {
    'x86_64': (2136544, 86176, 2136544, 187, 196, 2680, 1904),
    'arm64': (2069752, 68688, 2097152, 186, 196, 2774, 1872),
}
MAP_LIMIT = 4*1024*1024
RESOLVED = 0x4000
BIND = C.CFUNCTYPE(C.c_ulonglong, C.c_char_p)
CASES = {
    'version': ['--version'],
    'query': ['-batch', '-noheader', '-init', '/dev/null', ':memory:', 'SELECT 6*7;'],
}
DOWNLOAD_LIMIT = 8*1024*1024
IMAGE_LIMIT = 8*1024*1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def inventory(arch, image):
    if not 32 <= len(image) <= IMAGE_LIMIT:
        raise ValueError('SQLite executable is outside the inventory size bound')
    magic, cpu, subtype, kind, count, length, flags, reserved = struct.unpack_from('<8I', image)
    if (magic, cpu, kind, reserved) != (0xfeedfacf, TARGETS[arch][2], 2, 0):
        raise ValueError('expected a matching thin Mach-O executable')
    if count > 256 or length > len(image)-32:
        raise ValueError('invalid load command area')
    offset = 32
    segments, commands, dylibs = [], [], []
    entry = None
    chained = None
    for _ in range(count):
        if offset+8 > 32+length:
            raise ValueError('truncated load command')
        tag, size = struct.unpack_from('<II', image, offset)
        if size < 8 or size%8 or offset+size > 32+length:
            raise ValueError('invalid load command size')
        command = image[offset:offset+size]
        commands.append(hex(tag))
        if tag == 0x19:
            if size < 72:
                raise ValueError('truncated segment command')
            name, va, vm, off, file, maximum, prot, sections, attributes = struct.unpack_from(
                '<16s4Q4I', command, 8)
            if size != 72+sections*80 or off+file > len(image):
                raise ValueError('segment range exceeds file')
            segments.append(dict(name=name.rstrip(b'\0').decode('ascii'), va=va, vm=vm, offset=off,
                                 file=file, maximum=maximum, protection=prot, attributes=attributes))
        elif tag == 0x80000028:
            entry = struct.unpack_from('<Q', command, 8)[0]
        elif tag == 0x80000034:
            start, count_bytes = struct.unpack_from('<II', command, 8)
            if count_bytes < 28 or start+count_bytes > len(image):
                raise ValueError('chained fixup range exceeds file')
            header = struct.unpack_from('<7I', image, start)
            chained = dict(offset=start, bytes=count_bytes, version=header[0], imports=header[4],
                           imports_format=header[5], symbols_format=header[6])
        elif tag in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023):
            name = struct.unpack_from('<I', command, 8)[0]
            if not 24 <= name < size or b'\0' not in command[name:]:
                raise ValueError('invalid dylib name')
            dylibs.append(command[name:].split(b'\0', 1)[0].decode('ascii'))
        offset += size
    if offset != 32+length:
        raise ValueError('load commands do not cover their declared area')
    return dict(cpu=cpu, subtype=subtype, flags=flags, entry=entry, segments=segments,
                commands=commands, dylibs=dylibs, chained=chained)


def check_cases(cases):
    if set(cases) != set(CASES):
        raise ValueError('reference case inventory differs')
    for name, argv in CASES.items():
        case = cases[name]
        data = bytes.fromhex(case['stdout_hex'])
        if case['argv'] != argv or case['exit_code'] or case['stderr_hex']:
            raise ValueError(f'SQLite {name} returned an unexpected status or stderr')
        if name == 'version' and not data.startswith(VERSION.encode()+b' '):
            raise ValueError(f'unexpected SQLite version: {data!r}')
        if name == 'query' and data != b'42\n':
            raise ValueError(f'unexpected SQLite query result: {data!r}')


def reference(arch, out):
    if platform.system() != 'Darwin' or platform.machine() != arch:
        raise ValueError('SQLite reference runner architecture mismatch')
    flavor, expected, _ = TARGETS[arch]
    name = f'sqlite-tools-osx-{flavor}-3540100.zip'
    with urlopen(f'{RELEASE}/{name}', timeout=45) as response:
        archive = response.read(DOWNLOAD_LIMIT+1)
    if len(archive) > DOWNLOAD_LIMIT or hashlib.sha3_256(archive).hexdigest() != expected:
        raise ValueError('official SQLite archive SHA3-256 differs')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        members = [item for item in z.infolist() if PurePosixPath(item.filename).name == 'sqlite3']
        if len(members) != 1 or not 32 <= members[0].file_size <= IMAGE_LIMIT:
            raise ValueError('SQLite ZIP lacks a single bounded sqlite3 executable')
        image = z.read(members[0])
    if sha256(image) != IMAGE_SHA256[arch]:
        raise ValueError('SQLite executable SHA-256 differs')
    layout = inventory(arch, image)
    out.mkdir(parents=True, exist_ok=True)
    binary = (out/'sqlite3').resolve()
    binary.write_bytes(image)
    binary.chmod(0o755)
    results = {}
    for case, argv in CASES.items():
        run = subprocess.run([binary, *argv], cwd=out, env={'LC_ALL': 'C'},
                             stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        results[case] = dict(argv=argv, exit_code=run.returncode, stdout_hex=run.stdout.hex(),
                             stderr_hex=run.stderr.hex())
    check_cases(results)
    tool_hashes = {}
    for label, cmd in (('load-commands', ['otool', '-l']), ('imports', ['nm', '-m', '-u'])):
        output = subprocess.check_output([*cmd, binary], timeout=15)
        (out/f'{label}.txt').write_bytes(output)
        tool_hashes[label] = sha256(output)
    save_json(out/'reference.json', dict(schema='compact-macos-m92-sqlite-reference/v1',
              source_commit=source_head(), architecture=arch, archive_sha3_256=expected,
              image_sha256=sha256(image), image_bytes=len(image), cases=results,
              layout=layout, inventory_sha256=tool_hashes))
    print(f'{arch}: pinned {len(image)} SQLite bytes, {len(layout["segments"])} segments, '
          f'dependencies {layout["dylibs"]}')


def check_map(lib, arch, image, layout):
    if sha256(image) != IMAGE_SHA256[arch]:
        raise ValueError(f'{arch}: SQLite executable SHA-256 differs')
    arena, plan = C.create_string_buffer(MAP_LIMIT), Image()
    if lib.mac8_load(image, len(image), arena, len(arena), C.byref(plan)) != 1:
        raise ValueError(f'{arch}: bounded SQLite mapping failed')
    actual = (len(image), plan.entry, plan.mapped_bytes, plan.imports, plan.binds,
              plan.rebases, plan.bss_bytes)
    if actual != EXPECTED_MAP[arch] or plan.cpu != TARGETS[arch][2] or plan.entry != layout['entry']:
        raise ValueError(f'{arch}: mapped inventory differs: {actual}')
    access = lambda addr, size, rights: lib.mac8_access(C.byref(plan), BASE+addr, size, rights)
    text, const, data, link = plan.segments[1:]
    if (arena[:text.file_bytes] != image[:text.file_bytes] or
            arena[plan.bss:plan.bss+plan.bss_bytes] != bytes(plan.bss_bytes) or
            arena[len(image):plan.mapped_bytes] != bytes(plan.mapped_bytes-len(image)) or
            not access(plan.entry, 1, R|X) or access(plan.entry, 1, W) or
            not access(const.offset, const.bytes, R) or access(const.offset, 1, W|X) or
            access(const.offset, 1, W) or access(const.offset, 1, X) or
            not access(data.offset, data.bytes, R|W) or access(data.offset, 1, X) or
            not access(link.offset, link.bytes, R) or access(link.offset, 1, W) or
            access(plan.mapped_bytes, 1, R)):
        raise ValueError(f'{arch}: mapped contents or protections differ')

    fix = layout['chained']['offset']
    starts, imports, names = (fix+i for i in struct.unpack_from('<3I', image, fix+4))
    table = struct.unpack_from(f'<{plan.imports}I', image, imports)
    zlib = layout['dylibs'].index('/usr/lib/libz.1.dylib')+1
    system = layout['dylibs'].index('/usr/lib/libSystem.B.dylib')+1
    wanted_system = [int((value&511)==system) for value in table]
    if list(plan.system_import[:plan.imports]) != wanted_system or wanted_system.count(0) != 12:
        raise ValueError(f'{arch}: library identity differs')
    resolved, resolved_plan = C.create_string_buffer(MAP_LIMIT), Image()
    def resolve(_):
        return RESOLVED
    resolver = BIND(resolve)
    if lib.mac8_load_bound(image, len(image), resolved, len(resolved),
                           C.byref(resolved_plan), resolver) != 1:
        raise ValueError(f'{arch}: resolver mapping failed')
    counts = [0, 0]
    for index in (2, 3):
        rec = starts+struct.unpack_from('<I', image, starts+4+4*index)[0]
        pages = struct.unpack_from('<H', image, rec+20)[0]
        for page in range(pages):
            off = struct.unpack_from('<H', image, rec+22+page*2)[0]
            if off == 0xffff:
                continue
            slot = plan.segments[index].offset+page*plan.page+off
            while True:
                raw = struct.unpack_from('<Q', image, slot)[0]
                found = struct.unpack_from('<Q', arena, slot)[0]
                bound = struct.unpack_from('<Q', resolved, slot)[0]
                if raw>>63:
                    ordinal = raw&0xffffff
                    expected = UNRESOLVED+16*ordinal
                    mapped = RESOLVED if wanted_system[ordinal] else expected
                    counts[0] += 1
                else:
                    expected = mapped = BASE+(raw&0xfffffffff)
                    counts[1] += 1
                if (found, bound) != (expected, mapped):
                    raise ValueError(f'{arch}: incorrect fixup at {slot:#x}')
                step = ((raw>>51)&4095)*4
                if not step:
                    break
                slot += step
    if counts != [plan.binds, plan.rebases]:
        raise ValueError(f'{arch}: fixup counts differ')
    for i, value in enumerate(table):
        if plan.names[i] != names+(value>>9) or (value&511) not in (zlib, system):
            raise ValueError(f'{arch}: import inventory differs')

    load_commands = list(commands(image))
    rpath = next(off for tag, off in load_commands if tag == 0x8000001c)
    dylib = next(off for tag, off in load_commands if tag == 0xc)
    data_off = [off for tag, off in load_commands if tag == 0x19][3]
    chain = starts+struct.unpack_from('<I', image, starts+12)[0]
    invalid = {
        'unknown-library-ordinal': changed(image, imports, 'I', (table[0]&~511)|3),
        'weak-import': changed(image, imports, 'I', table[0]|256),
        'unsupported-dylib': changed(image, dylib+24, 'B', ord('x')),
        'unsupported-rpath': changed(image, rpath+12, 'B', ord('x')),
        'common-outside-data': changed(image, data_off+72+2*80+32, 'Q',
                                       layout['segments'][4]['va']),
        'chain-page-count': changed(image, chain+20, 'H', 0xffff),
    }
    sentinel = b'\xa5'*MAP_LIMIT
    denied = C.create_string_buffer(sentinel, MAP_LIMIT)
    reject_plan = Image()
    for name, bad in invalid.items():
        if (lib.mac8_load(bad, len(bad), denied, len(denied), C.byref(reject_plan)) or
                denied.raw != sentinel or any(bytes(reject_plan))):
            raise ValueError(f'{arch}: loader accepted or modified state for {name}')
    return dict(loader_admitted=True, mapped_bytes=plan.mapped_bytes, binds=plan.binds,
                rebases=plan.rebases, libz_imports=12, rejected=sorted(invalid))


def audit(lib, references, output):
    lib = C.CDLL(str(lib.resolve()))
    lib.mac8_load.argtypes = [C.c_void_p, C.c_uint, C.c_void_p, C.c_uint, C.POINTER(Image)]
    lib.mac8_load_bound.argtypes = lib.mac8_load.argtypes+[BIND]
    lib.mac8_access.argtypes = [C.POINTER(Image), C.c_ulonglong, C.c_uint, C.c_uint]
    commit = source_head()
    results = {}
    for arch in TARGETS:
        ref = references/f'macos-m92-sqlite-{arch}'
        image = (ref/'sqlite3').read_bytes()
        receipt = json.loads((ref/'reference.json').read_text())
        tools = {name: sha256((ref/f'{name}.txt').read_bytes()) for name in ('load-commands', 'imports')}
        layout = inventory(arch, image)
        if any(receipt.get(key) != value for key, value in dict(
                schema='compact-macos-m92-sqlite-reference/v1', source_commit=commit, architecture=arch,
                archive_sha3_256=TARGETS[arch][1], image_sha256=sha256(image), image_bytes=len(image),
                layout=layout, inventory_sha256=tools).items()):
            raise ValueError(f'{arch}: SQLite receipt provenance differs')
        check_cases(receipt['cases'])
        mapped = check_map(lib, arch, image, layout)
        results[arch] = dict(reference=receipt, **mapped, guest_execution_verified=False)
        print(f'{arch}: mapped {mapped["mapped_bytes"]} bytes, {mapped["binds"]} binds, '
              f'{mapped["rebases"]} rebases')
    output.parent.mkdir(parents=True, exist_ok=True)
    save_json(output, dict(schema='compact-macos-m92-sqlite-admission/v1',
                           source_commit=commit, architectures=results))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='command', required=True)
    ref = subcommands.add_parser('reference')
    ref.add_argument('arch', choices=TARGETS)
    ref.add_argument('out', type=Path)
    gate = subcommands.add_parser('audit')
    for arg in ('loader', 'references', 'output'):
        gate.add_argument(arg, type=Path)
    args = parser.parse_args()
    if args.command == 'reference':
        reference(args.arch, args.out)
    else:
        audit(args.loader, args.references, args.output)
