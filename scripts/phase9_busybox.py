# SPDX-License-Identifier: AGPL-3.0-only
"""Pinned historical BusyBox applets: compatibility fixtures, not a distribution."""
import hashlib
from pathlib import Path
import re
import urllib.request

URL = 'https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/'
FIXTURES = {
    'true': ('busybox_TRUE', '1f0ff7453cc0bc2533b3426226b91e05b6ed995388b55f7ce20a0e13ac8ae0bb'),
    'echo': ('busybox_ECHO', 'b9d380e2088909c717331eaddf075a7f34d15ee18b1afa1be1a019c1b9b79ff5'),
    'printf': ('busybox_PRINTF', '9c6d0dbab75b3fb82ed469938d8e63544be91b94310b5c8af745ca73065817c5'),
}


def verify(data, name):
    if len(data) > 4 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != FIXTURES[name][1]:
        raise ValueError('BusyBox fixture digest mismatch: ' + name)
    return data


def fetch(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, (remote, _) in FIXTURES.items():
        destination = directory / ('busybox-' + name)
        if destination.exists():
            data = destination.read_bytes()
        else:
            with urllib.request.urlopen(URL + remote, timeout=45) as response:
                data = response.read(4 * 1024 * 1024 + 1)
        verify(data, name)
        destination.write_bytes(data)
        destination.chmod(0o700)


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('expected source commit')
    operations = []
    for name in FIXTURES:
        operations += [f'hget http://10.0.2.2:8000/busybox-{name} > /tmp/bb-{name}',
                       f'sha1sum -2 256 /tmp/bb-{name}']
    operations += ['echo FLEX_BUSYBOX_BEGIN',
                   '/amd64/bin/compact-linux -p /tmp/bb-true && echo FLEX_BUSYBOX_TRUE_OK',
                   f'/amd64/bin/compact-linux -p /tmp/bb-echo BB_{commit} && echo FLEX_BUSYBOX_ECHO_OK',
                   "/amd64/bin/compact-linux -p /tmp/bb-printf '%d %x\\n' 123 255 && echo FLEX_BUSYBOX_PRINTF_OK",
                   'echo FLEX_BUSYBOX_END']
    return [op + f'; echo RYZOVA_RUNTIME_STAGE_{68+i}' for i, op in enumerate(operations)] + ['echo FLEX_BUSYBOX_DONE']


def inspect(serial, commit):
    def line(raw, value):
        return re.search(rb'(?:^|\r?\n)' + re.escape(value) + rb'(?:\r?\n|$)', raw) is not None
    section = re.search(rb'(?:^|\r?\n)FLEX_BUSYBOX_BEGIN\r?\n(.*?)\r?\nFLEX_BUSYBOX_END(?:\r?\n|$)', serial, re.S)
    body = section.group(1) if section else b''
    results = re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)', body)
    checks = {name: line(body, f'FLEX_BUSYBOX_{name.upper()}_OK'.encode()) for name in FIXTURES}
    checks.update({'source_challenge': line(body, f'BB_{commit}'.encode()),
                   'formatted_output': line(body, b'123 ff'), 'clean_results': len(results) == 3,
                   'done': line(serial, b'FLEX_BUSYBOX_DONE'),
                   'stages': all(line(serial, f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(68, 79)),
                   'digests': all(re.search(rb'(?:^|\r?\n)' + digest.encode() + rb'\s+/tmp/bb-' + name.encode() + rb'(?:\r?\n|$)', serial)
                                  for name, (_, digest) in FIXTURES.items()),
                   'no_panic': re.search(rb'(?im)^panic:', serial) is None})
    return {'schema': 'flex-linux-busybox-applets/v1', 'source_commit': commit,
            'checks': {k: bool(v) for k, v in checks.items()}, 'passed': all(checks.values()),
            'fixtures': {k: v[1] for k, v in FIXTURES.items()},
            'shell_qualified': False, 'general_linux_compatibility': False,
            'physical_hardware_qualified': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', required=True)
    fetch(parser.parse_args().fetch)
