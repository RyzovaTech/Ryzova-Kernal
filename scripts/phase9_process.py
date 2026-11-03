# SPDX-License-Identifier: AGPL-3.0-only
"""Compile a real freestanding Linux C program and inspect native evidence."""
import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ['-O1', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
         '-fno-asynchronous-unwind-tables', '-fcf-protection=none', '-fno-pie',
         '-fno-tree-vectorize', '-mno-sse', '-mno-mmx', '-nostdlib', '-static',
         '-no-pie', '-Wl,--build-id=none']


def build(output):
    output = Path(output)
    subprocess.run(['cc', *FLAGS, str(ROOT / 'tests/fixtures/compact_process_start.S'),
                    str(ROOT / 'tests/fixtures/compact_process.c'), '-o', str(output)],
                   check=True, capture_output=True)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('expected source commit')
    operations = [
        'hget http://10.0.2.2:8000/process-compiled.elf > /tmp/p-compiled',
        'echo FLEX_PROCESS_BEGIN',
        f"/amd64/bin/compact-linux -p -e 'FLEX_MODE=test' /tmp/p-compiled PC_{commit} && echo FLEX_PROCESS_EXIT_OK",
        'echo FLEX_PROCESS_END',
        'sha1sum -2 256 /tmp/p-compiled',
        '/amd64/bin/compact-linux -p -i /tmp/flex-input /tmp/f-copy > /tmp/p-copy && echo FLEX_PROCESS_FILE_OK',
        'cmp /tmp/p-copy /tmp/flex-input && echo FLEX_PROCESS_FILE_DIGEST_OK',
    ]
    return [op + f'; echo RYZOVA_RUNTIME_STAGE_{60+i}' for i, op in enumerate(operations)] + ['echo FLEX_PROCESS_DONE; echo RYZOVA_RUNTIME_STAGE_67']


def inspect(build_serial, serial, commit, digest):
    def line(raw, value):
        return re.search(rb'(?:^|\r?\n)' + re.escape(value) + rb'(?:\r?\n|$)', raw) is not None
    section = re.search(rb'(?:^|\r?\n)FLEX_PROCESS_BEGIN\r?\n(.*?)\r?\nFLEX_PROCESS_END(?:\r?\n|$)', serial, re.S)
    checks = {'native_build': line(build_serial, b'COMPACT_NATIVE_BUILD_OK'),
              'c_program': section is not None and line(section.group(1), b'FLEX_COMPILED_C_OK'),
              'argv_challenge': section is not None and line(section.group(1), f'PC_{commit}'.encode()),
              'clean_exit': section is not None and line(section.group(1), b'FLEX_PROCESS_EXIT_OK'),
              'startup_memory_syscalls': section is not None and re.search(
                  rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=13(?:\r?\n|$)', section.group(1)) is not None,
              'stages': all(line(serial, f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(60,60+len(commands(commit))-1)),
              'explicit_file_grant': line(serial,b'FLEX_PROCESS_FILE_OK') and line(serial,b'FLEX_PROCESS_FILE_DIGEST_OK'),
              'done': line(serial,b'FLEX_PROCESS_DONE'),
              'no_panic': re.search(rb'(?im)^panic:',serial) is None,
              'input_digest': isinstance(digest,str) and re.fullmatch('[a-f0-9]{64}',digest) is not None and re.search(
                  rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/p-compiled(?:\r?\n|$)',serial) is not None}
    return {'schema':'flex-linux-compiled-process/v1', 'source_commit':commit,
            'checks':checks,'passed':all(checks.values()),'elf_sha256':digest,
            'general_linux_compatibility':False,'libc_dynamic_linker':False,
            'signals_threads':False,'physical_hardware_qualified':False}
