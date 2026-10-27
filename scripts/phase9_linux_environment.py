# SPDX-License-Identifier: AGPL-3.0-only
"""Reproducible Linux ELF file workload and native environment evidence."""
import hashlib
import re
import struct


class Code:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []

    def emit(self, value):
        self.code.extend(value)

    def label(self, name):
        self.labels[name] = len(self.code)

    def branch(self, opcode, label):
        self.emit(opcode)
        self.fixups.append((len(self.code), label))
        self.emit(bytes(4))

    def imm(self, reg, value, wide=False):
        self.emit((b'\x48' if wide else b'') + bytes([0xb8 + reg]))
        self.emit(struct.pack('<Q' if wide else '<I', value & ((1 << (64 if wide else 32)) - 1)))

    def lea(self, reg, address):
        delta = address - (0x400100 + len(self.code) + 7)
        self.emit(bytes([0x48, 0x8d, 5 | (reg << 3)]) + struct.pack('<i', delta))

    def syscall(self, nr):
        self.imm(0, nr)
        self.emit(b'\x0f\x05')

    def finish(self):
        for offset, name in self.fixups:
            self.code[offset:offset + 4] = struct.pack('<i', self.labels[name] - offset - 4)
        return bytes(self.code)


def image(code, data):
    if len(code) > 0x700 or len(data) > 0x800:
        raise ValueError('fixture exceeds RX segment')
    out = bytearray(4096)
    out[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                          2, 62, 1, 0x400100, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    out[64:120] = struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 4096, 4096, 4096)
    out[120:176] = struct.pack('<IIQQQQQQ', 1, 6, 4096, 0x401000, 0x401000, 0, 4096, 4096)
    out[256:256 + len(code)] = code
    out[2048:2048 + len(data)] = data
    return bytes(out)


def exit_paths(c):
    c.imm(7, 0)
    c.syscall(60)
    c.label('fail')
    c.imm(7, 71)
    c.syscall(60)


def copy_elf():
    c = Code()
    for flags, address, save in ((0, 0x400800, b'\x48\x89\xc5'),
                                 (513, 0x400806, b'\x48\x89\xc3')):
        c.imm(7, -100, True)
        c.lea(6, address)
        c.imm(2, flags)
        c.syscall(257)
        c.emit(b'\x48\x85\xc0')
        c.branch(b'\x0f\x88', 'fail')
        c.emit(save)
    c.label('loop')
    c.emit(b'\x48\x89\xef')  # rdi = rbp (input fd)
    c.imm(6, 0x401000, True)
    c.imm(2, 256)
    c.syscall(0)
    c.emit(b'\x48\x85\xc0')
    c.branch(b'\x0f\x88', 'fail')
    c.branch(b'\x0f\x84', 'done')
    c.emit(b'\x48\x89\xc2\x48\x89\xdf')  # rdx = rax; rdi = rbx
    c.syscall(1)
    c.emit(b'\x48\x39\xd0')  # cmp rdx, rax
    c.branch(b'\x0f\x85', 'fail')
    c.branch(b'\xe9', 'loop')
    c.label('done')
    c.emit(b'\x48\x89\xef')
    c.syscall(3)
    c.emit(b'\x48\x89\xdf')
    c.syscall(3)
    exit_paths(c)
    return image(c.finish(), b'input\0output\0')


def denied_elf(path, expected, flags=0, readonly_memory=False):
    c = Code()
    c.imm(7, -100, True)
    c.lea(6, 0x400800)
    c.imm(2, flags)
    c.syscall(257)
    if readonly_memory:
        c.emit(b'\x48\x89\xc7')
        c.imm(6, 0x400800, True)
        c.imm(2, 1)
        c.syscall(0)
    c.imm(3, expected, True)
    c.emit(b'\x48\x39\xd8')
    c.branch(b'\x0f\x85', 'fail')
    exit_paths(c)
    return image(c.finish(), path.encode() + b'\0')


def fixtures():
    return {'copy': copy_elf(), 'deny': denied_elf('/etc/passwd', -2),
            'traverse': denied_elf('../input', -13),
            'readonly': denied_elf('input', -13, 1),
            'rxwrite': denied_elf('input', -14, readonly_memory=True)}


def payload(commit):
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('expected source commit')
    # Binary data including NULs, with several read iterations and a short tail.
    return (f'FLEX_FILES_{commit}\n'.encode() + bytes(range(256))) * 13 + b'END\0\xff\n'


def commands():
    result = []
    operations = [
        'mkdir -p /tmp/compact-root; /amd64/bin/compact-linux-fs /tmp/compact-root; bind -a /tmp/compact-root /',
        'echo FLEX_API_BEGIN; cat /compact/linux/api; cat /compact/linux/abi; echo FLEX_API_END',
        "@{echo no > /compact/linux/api}; if(! ~ $status '') echo FLEX_API_READONLY_OK",
        'hget http://10.0.2.2:8000/flex-input.bin > /tmp/flex-input',
    ]
    for name in fixtures():
        operations.append(f'hget http://10.0.2.2:8000/flex-{name}.elf > /tmp/f-{name}')
        operations.append(f'/amd64/bin/compact-linux -i /tmp/flex-input /tmp/f-{name} > /tmp/o-{name} '
                          f'&& echo FLEX_{name}_OK')
    operations.extend([
        'sha1sum -2 256 /tmp/o-copy',
        '/amd64/bin/compact-linux -i /tmp/o-copy /tmp/f-copy > /tmp/flex-second && echo FLEX_SECOND_OK',
        'cmp /tmp/flex-input /tmp/flex-second && echo FLEX_ISOLATED_COPY_OK',
        '/amd64/bin/compact-linux /tmp/f-copy > /tmp/flex-no-grant; if(! ~ $status \'\') echo FLEX_NO_GRANT_OK',
    ])
    for i, operation in enumerate(operations, 37):
        command = operation + f'; echo RYZOVA_RUNTIME_STAGE_{i}'
        if len(command) > 220:
            raise ValueError('serial line too long')
        result.append(command)
    result.append('echo RYZOVA_LINUX_ENV_DONE')
    return result


def inspect(build, serial, commit):
    def line(raw, value):
        return re.search(rb'(?:^|\r?\n)' + re.escape(value) + rb'(?:\r?\n|$)', raw) is not None
    checks = {'service_build': line(build, b'COMPACT_SERVICE_BUILD_OK'),
              'stages': all(line(serial, f'RYZOVA_RUNTIME_STAGE_{i}'.encode())
                            for i in range(37, 37 + len(commands()) - 1)),
              'namespace_api': line(serial, b'compact/linux api=1.0 profile=files-v1'),
              'abi_profile': line(serial, b'linux-amd64-static-subset-v1'),
              'metadata_readonly': line(serial, b'FLEX_API_READONLY_OK'),
              'isolated_repeat': line(serial, b'FLEX_ISOLATED_COPY_OK') and line(serial, b'FLEX_SECOND_OK'),
              'grant_required': line(serial, b'FLEX_NO_GRANT_OK'),
              'complete': line(serial, b'RYZOVA_LINUX_ENV_DONE'),
              'no_panic': re.search(rb'(?im)^panic:', serial) is None}
    for name in fixtures():
        checks[name] = line(serial, f'FLEX_{name}_OK'.encode())
    digest = hashlib.sha256(payload(commit)).hexdigest()
    checks['output_digest'] = re.search(rb'(?:^|\r?\n)' + digest.encode() + rb'\s+/tmp/o-copy(?:\r?\n|$)', serial) is not None
    return {'schema': 'flex-linux-files-environment/v1', 'source_commit': commit,
            'checks': checks, 'passed': all(checks.values()), 'output_sha256': digest,
            'profile': 'linux-amd64-static-files-v1', 'general_linux_compatibility': False,
            'dynamic_linker': False, 'threads': False, 'signals': False,
            'metadata_grants_execution': False, 'physical_hardware_qualified': False}
