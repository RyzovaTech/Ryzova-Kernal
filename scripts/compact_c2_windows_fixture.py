# SPDX-License-Identifier: GPL-3.0-only
"""PE fixture for a read-only handle write, exclusive create and truncate."""
import struct

from compact_c1_jq_contract import INPUT_NAME
from compact_c2_file_contract import CREATED_NAME
from compact_windows_w3 import Code, imported_pe

APIS = ('CreateFileW', 'WriteFile', 'GetLastError', 'CloseHandle', 'ExitProcess')


def fixture():
    code = Code().emit('4883ec48')  # Shadow space and aligned nested calls.
    payload = bytearray()
    for name in (INPUT_NAME, CREATED_NAME):
        payload += (name + '\0').encode('utf-16-le').ljust(64, b'\0')
    payload += b'X\0\0\0' + bytes(4)

    def call(name):
        code.call(name, APIS)

    def require(condition, code_on_failure):
        # Branch over ExitProcess on success. The stack stays aligned.
        code.emit(bytes((condition, 11)))
        code.emit(b'\xb9' + struct.pack('<I', code_on_failure))
        call('ExitProcess')

    def open_file(path, access, disposition):
        code.lea('rcx', path)
        code.emit(b'\xba' + struct.pack('<I', access))
        code.emit('4531c0 4531c9 48c7442420' + struct.pack('<I', disposition).hex() +
                  ' 48c744242800000000 48c744243000000000')
        call('CreateFileW')

    def denied(failure):
        call('GetLastError')
        code.emit('83f805')  # ERROR_ACCESS_DENIED
        require(0x74, failure)

    open_file(0x2400, 0x80000000, 3)  # OPEN_EXISTING, GENERIC_READ
    code.emit('4883f8ff')
    require(0x75, 11)
    code.emit('4889c3 4889c1')  # Save the handle in nonvolatile RBX.
    code.lea('rdx', 0x2480).emit('41b801000000').lea('r9', 0x2484)
    code.emit('48c744242000000000')
    call('WriteFile')
    code.emit('85c0')
    require(0x74, 12)
    denied(13)
    code.emit('4889d9')
    call('CloseHandle')
    code.emit('85c0')
    require(0x75, 14)
    for path, disposition, failure in ((0x2440, 1, 15), (0x2400, 5, 17)):
        open_file(path, 0x40000000, disposition)  # CREATE_NEW, TRUNCATE_EXISTING
        code.emit('4883f8ff')
        require(0x74, failure)
        denied(failure + 1)
    code.emit('31c9')
    call('ExitProcess')
    return imported_pe(code.bytes, APIS, bytes(payload))
