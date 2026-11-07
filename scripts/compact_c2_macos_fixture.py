# SPDX-License-Identifier: GPL-3.0-only
"""Build a test-only Mach-O by replacing jq's entry with a small API probe.

The pinned image supplies the bounded loader layout and libSystem import
table. The original reference image is never modified.
"""
import struct

from compact_c1_jq_contract import INPUT_NAME
from compact_c2_file_contract import CREATED_NAME

BASE = 0x200000
IMPORT_BASE = 0x10000
DATA_OFFSET = 0x200


def layout(image):
    commands = {}
    offset = 32
    for _ in range(struct.unpack_from('<I', image, 16)[0]):
        kind, size = struct.unpack_from('<II', image, offset)
        commands[kind] = offset
        offset += size
    entry = struct.unpack_from('<Q', image, commands[0x80000028]+8)[0]
    fixups = struct.unpack_from('<I', image, commands[0x80000034]+8)[0]
    imports, symbols, count = struct.unpack_from('<III', image, fixups+8)
    tokens = {}
    for i in range(count):
        name = struct.unpack_from('<I', image, fixups+imports+4*i)[0] >> 9
        at = fixups+symbols+name
        tokens[image[at:image.index(0, at)].decode()] = IMPORT_BASE+16*i
    return entry, tokens


def intel(tokens, args):
    code = bytearray.fromhex('4883ec08')  # Maintain the SysV alignment at each call.

    def emit(text):
        code.extend(bytes.fromhex(text))

    def immediate(opcode, value):
        code.extend(bytes((opcode,)) + struct.pack('<I', value))

    def call(name):
        immediate(0xb8, tokens[name])
        emit('ffd0')

    def exit_guest(status):
        immediate(0xbf, status)
        call('_exit')

    def require(branch, status):
        emit(f'{branch:02x}0c')  # Skip the 12-byte failure exit on success.
        exit_guest(status)

    def open_file(name, mode):
        immediate(0xbf, args[name])
        immediate(0xbe, args[mode])
        call('_fopen$DARWIN_EXTSN')
        emit('4885c0')

    def errno(number, status):
        call('___error')
        emit(f'8338{number:02x}')
        require(0x74, status)

    open_file(INPUT_NAME, 'rb')
    require(0x75, 11)
    emit('4889c3 4889c1')  # RBX preserves the FILE across service calls.
    immediate(0xbf, args['X'])
    immediate(0xbe, 1)
    immediate(0xba, 1)
    call('_fwrite')
    emit('4885c0')
    require(0x74, 12)
    errno(9, 13)
    emit('4889df')
    call('_fclose')
    emit('85c0')
    require(0x74, 14)
    for name, mode, status in ((CREATED_NAME, 'a', 15), (INPUT_NAME, 'w', 17)):
        open_file(name, mode)
        require(0x74, status)
        errno(13, status+1)
    exit_guest(0)
    return code


def arm(tokens, args):
    code = []

    def immediate(reg, value):
        code.append(0xd2800000 | ((value & 0xffff) << 5) | reg)  # MOVZ
        if value >> 16:
            code.append(0xf2a00000 | ((value >> 16) << 5) | reg)  # MOVK, LSL 16

    def call(name):
        immediate(16, tokens[name])
        code.append(0xd63f0200)  # BLR X16

    def exit_guest(status):
        immediate(0, status)
        call('_exit')

    def require(branch, status):
        # Branch over MOVZ W0, MOVZ/MOVK X16, BLR X16 on success.
        code.append(branch | (5 << 5))
        exit_guest(status)

    def open_file(name, mode):
        immediate(0, args[name])
        immediate(1, args[mode])
        call('_fopen$DARWIN_EXTSN')

    def errno(number, status):
        call('___error')
        code.append(0xb9400000)  # LDR W0, [X0]
        code.append(0x7100001f | (number << 10))  # CMP W0, #number
        require(0x54000000, status)  # B.EQ

    open_file(INPUT_NAME, 'rb')
    require(0xb5000000, 11)  # CBNZ X0
    code.extend((0xaa0003f3, 0xaa0003e3))  # MOV X19, X0; MOV X3, X0
    immediate(0, args['X'])
    immediate(1, 1)
    immediate(2, 1)
    call('_fwrite')
    require(0xb4000000, 12)  # CBZ X0
    errno(9, 13)
    code.append(0xaa1303e0)  # MOV X0, X19
    call('_fclose')
    require(0x34000000, 14)  # CBZ W0
    for name, mode, status in ((CREATED_NAME, 'a', 15), (INPUT_NAME, 'w', 17)):
        open_file(name, mode)
        require(0xb4000000, status)
        errno(13, status+1)
    exit_guest(0)
    return struct.pack(f'<{len(code)}I', *code)


def fixture(arch, image):
    entry, tokens = layout(image)
    data = bytearray()
    args = {}
    for text in (INPUT_NAME, CREATED_NAME, 'rb', 'a', 'w', 'X'):
        args[text] = BASE+entry+DATA_OFFSET+len(data)
        data += text.encode() + b'\0'
    code = {'x86_64': intel, 'arm64': arm}[arch](tokens, args)
    if len(code) > DATA_OFFSET or entry+DATA_OFFSET+len(data) > len(image):
        raise ValueError('mutation fixture exceeds entry area')
    result = bytearray(image)
    result[entry:entry+len(code)] = code
    at = entry+DATA_OFFSET
    result[at:at+len(data)] = data
    return bytes(result)
