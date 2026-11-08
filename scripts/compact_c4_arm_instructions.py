# SPDX-License-Identifier: GPL-3.0-only
"""Boundary probes in a test-only copy of the pinned ARM64 Mach-O."""
import ctypes as C
import struct
from compact_c2_macos_fixture import layout
from compact_macos_m8_loader_check import ARENA, BASE, GUARD, Stop


def check_arm_instructions(lib, image):
    entry, tokens = layout(image)
    data_at = entry+0x800
    payload = bytes(range(16))+bytes([0, 255, 128, 127])*4
    source = payload[:16]
    second = payload[16:]
    checks = 0

    def mov(reg, value):
        return [0xd2800000 | ((value & 65535)<<5) | reg,
                0xf2a00000 | (((value>>16) & 65535)<<5) | reg]

    def run(ops, expected, word=0, data=payload, rejected=False):
        nonlocal checks
        # Read-only vector sources, preserved upper lanes, and a stack result.
        code = mov(9, BASE+data_at)+[0x3dc00120, 0x3dc00521]
        code += mov(23, 0x89abcdef)+ops
        if not rejected:
            code += [0xd10043ff, 0x3d8003e0, 0xb94003e0 | (word<<10)]
            code += mov(10, expected & 0xffffffff)+[0x6b0a001f, 0x1a9f07e0]
            code += mov(16, tokens['_exit'])+[0xd63f0200]
        probe = bytearray(image)
        probe[entry:entry+len(code)*4] = struct.pack('<'+'I'*len(code), *code)
        probe[data_at:data_at+len(data)] = data
        stop = Stop()
        args = (C.c_char_p*1)(b'probe')
        status = lib.mac9_run(bytes(probe), len(probe), C.create_string_buffer(ARENA),
                             ARENA, GUARD, 1, args, 1000, None, None, 0, C.byref(stop))
        if rejected:
            if status != 0:
                raise ValueError(f'ARM reserved instruction admitted: {ops!r}, {status}')
        elif (status, stop.exit_code) != (2, 0):
            raise ValueError(f'ARM instruction {ops!r} word {word}: '
                             f'{status}, {stop.exit_code:#x} != {expected:#x} at {stop.last_pc:#x}')
        checks += 1

    def vector(op, expected, data=payload):
        for word in range(4):
            run([op], int.from_bytes(expected[word*4:word*4+4], 'little'), word, data)

    for width in (1, 2, 4, 8):
        for lane in (0, 16//width-1):
            imm = width*(2*lane+1)
            op = 0x4e001c00 | (imm<<16) | (23<<5)
            expected = bytearray(source)
            expected[lane*width:(lane+1)*width] = (0x89abcdef).to_bytes(8, 'little')[:width]
            vector(op, expected)
    for lane in range(16):
        op = 0x0d400000 | ((lane//8)<<30) | (((lane%8)//4)<<12) | ((lane%4)<<10) | (9<<5)
        expected = bytearray(source); expected[lane] = source[0]
        vector(op, expected)
    for lane in range(8):
        op = 0x0d404000 | ((lane//4)<<30) | (((lane%4)//2)<<12) | ((lane%2)<<11) | (9<<5)
        expected = bytearray(source); expected[lane*2:lane*2+2] = source[:2]
        vector(op, expected)
    for q in (0, 1):
        size = 16 if q else 8
        for xor in (0, 1):
            expected = bytes((a^b if xor else a&b) for a,b in zip(source[:size], second[:size]))+bytes(16-size)
            vector(0x0e211c00 | (q<<30) | (xor<<29), expected)
        # ZIP2 uses a temporary even when the destination aliases its first source.
        expected = b''.join(source[size//2+i:size//2+i+4]+second[size//2+i:size//2+i+4]
                            for i in range(0, size//2, 4))+bytes(16-size)
        vector(0x0e817800 | (q<<30), expected)
    for width in (1, 2, 4):
        for upper in (0, 1):
            for signed in (0, 1):
                size = width*8
                for shift in (0, size-1):
                    half = second[8*upper:8*upper+8]
                    vals = [int.from_bytes(half[i:i+width], 'little', signed=bool(signed))<<shift
                            for i in range(0, 8, width)]
                    expected = b''.join((v & ((1<<(size*2))-1)).to_bytes(width*2, 'little') for v in vals)
                    op = 0x0f00a420 | ((size+shift)<<16) | (upper<<30) | ((1-signed)<<29)
                    vector(op, expected)
    for size in (0, 1, 2, 3):
        width = 1<<size
        for q in (0, 1):
            op = 0x0e209820 | (size<<22) | (q<<30)
            if size==3 and not q:
                run([op], 0, rejected=True)
                continue
            length = 16 if q else 8
            data = bytes([0, 0, 0, 0, 1, 0, 0, 0])*4
            expected = b''.join(bytes([0 if any(data[16+i:16+i+width]) else 255])*width
                                for i in range(0, length, width))+bytes(16-length)
            vector(op, expected, data)
    for sub in (0, 1):
        a = struct.unpack('<4I', source)
        b = struct.unpack('<4I', second)
        expected = struct.pack('<4I', *((x-x*y if sub else x+x*y) & 0xffffffff for x,y in zip(a,b)))
        vector(0x4e819400 | (sub<<29), expected)
        for q in (0, 1):
            length = 16 if q else 8
            vals = [(x-y if sub else x+y) & 0xffffffff for x,y in zip(a,b)]
            expected = struct.pack('<4I', *vals)[:length]+bytes(16-length)
            vector(0x0ea18400 | (q<<30) | (sub<<29), expected)
    for invert in (0, 1):
        for q in (0, 1):
            for mode in (0, 2, 4, 6, 8, 10):
                width = 4 if mode<8 else 2
                value = 9<<((mode%(width*2))*4)
                if invert:
                    value ^= (1<<(width*8))-1
                size = 16 if q else 8
                expected = value.to_bytes(width, 'little')*(size//width)+bytes(16-size)
                vector(0x0f000520 | (q<<30) | (invert<<29) | (mode<<12), expected)
    for size in range(5):
        width = 1<<size
        # B/H/S/D/Q loads clear all bits above the loaded element.
        op = 0x3d400120 | (size<<30) if size<4 else 0x3dc00120
        vector(op, source[:width]+bytes(16-width))
        op = 0x3c400120 | (size<<30) if size<4 else 0x3cc00120
        vector(op, source[:width]+bytes(16-width))
    # REV16 W23/X23, followed by copying the scalar result into the vector.
    for wide in (0, 1):
        value = int.from_bytes(bytes.fromhex('cdef89ab00000000'), 'little')
        run([0x5ac00400 | (wide<<31) | (23<<5) | 23, 0x4e081ee0], value & 0xffffffff)
        run([0x5ac00400 | (wide<<31) | (23<<5) | 23, 0x4e081ee0], value>>32, 1)
    for op in (0x4e001c00, 0x0d404400, 0x0f40a400, 0x7dc00120):
        run([op], 0, rejected=True)
    return dict(arm_instruction_checks=checks)
