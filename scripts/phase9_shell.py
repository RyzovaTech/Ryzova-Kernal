# SPDX-License-Identifier: AGPL-3.0-only
"""Unmodified multicall BusyBox and bounded ash script qualification."""
import hashlib
from pathlib import Path
import re
import urllib.request

URL = 'https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox'
DIGEST = '6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348'
SCRIPT = b'''f() { printf 'sum=%s\\n' "$1"; }
x=0; for n in 1 2 3; do x=$((x+n)); done
test -f /input || exit 71
test ! -e /etc/passwd || exit 72
echo FLEX_SHELL_OK
printf '%s\\n' "$1"
f "$x"
cd /tmp || exit 73
pwd
'''
DATA = b'FLEX_SHELL_INPUT\n'


def fetch(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'busybox'
    if path.exists():
        data = path.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=45) as response:
            data = response.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('multicall BusyBox fixture digest mismatch')
    path.write_bytes(data)
    path.chmod(0o700)
    (directory / 'shell-script').write_bytes(SCRIPT)
    (directory / 'shell-data').write_bytes(DATA)


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('expected source commit')
    ops = ['hget http://10.0.2.2:8000/busybox > /tmp/busybox',
           'sha1sum -2 256 /tmp/busybox',
           'hget http://10.0.2.2:8000/shell-script > /tmp/shell-script',
           'hget http://10.0.2.2:8000/shell-data > /tmp/shell-data',
           'sha1sum -2 256 /tmp/shell-script', 'sha1sum -2 256 /tmp/shell-data',
           'echo FLEX_SHELL_BEGIN',
           f'/amd64/bin/compact-linux -p -i /tmp/shell-script /tmp/busybox ash /input SH_{commit} && echo FLEX_SHELL_SCRIPT_OK',
           '/amd64/bin/compact-linux -p -i /tmp/shell-data /tmp/busybox cat /input > /tmp/shell-cat && cmp /tmp/shell-cat /tmp/shell-data && echo FLEX_SHELL_CAT_OK',
           '/amd64/bin/compact-linux -p -i /tmp/shell-data /tmp/busybox wc -c /input && echo FLEX_SHELL_WC_OK',
           '''/amd64/bin/compact-linux -p -i /tmp/shell-data /tmp/busybox ash -c 'read x </input; echo "$x"' && echo FLEX_SHELL_READ_OK''',
           "/amd64/bin/compact-linux -p -i /tmp/shell-data /tmp/busybox ash -c 'echo first >/output; echo second >>/output' && echo FLEX_SHELL_REDIRECT_OK",
           'echo FLEX_SHELL_END']
    return [op + f'; echo RYZOVA_RUNTIME_STAGE_{80+i}' for i, op in enumerate(ops)] + ['echo FLEX_SHELL_DONE']


def inspect(serial, commit):
    def line(raw, text):
        return re.search(rb'(?:^|\r?\n)' + re.escape(text) + rb'(?:\r?\n|$)', raw) is not None
    section = re.search(rb'(?:^|\r?\n)FLEX_SHELL_BEGIN\r?\n(.*?)\r?\nFLEX_SHELL_END(?:\r?\n|$)', serial, re.S)
    body = section.group(1) if section else b''
    checks = {name: line(body, ('FLEX_SHELL_' + name + '_OK').encode()) for name in ('SCRIPT', 'CAT', 'WC', 'READ', 'REDIRECT')}
    results = re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)', body)
    checks.update({'shell': line(body, b'FLEX_SHELL_OK'), 'challenge': line(body, ('SH_' + commit).encode()),
                   'arithmetic_function': line(body, b'sum=6'), 'cwd': line(body, b'/tmp'),
                   'read': line(body, DATA.strip()), 'redirect': line(body, b'first') and line(body, b'second'),
                   'wc_bytes': re.search(rb'(?:^|\r?\n)\s*17 /input(?:\r?\n|$)', body) is not None,
                   'clean_results': len(results) == 5,
                   'stages': all(line(serial, f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(80, 93)),
                   'done': line(serial, b'FLEX_SHELL_DONE'), 'no_panic': re.search(rb'(?im)^panic:', serial) is None})
    for path, digest in (('busybox', DIGEST), ('shell-script', hashlib.sha256(SCRIPT).hexdigest()), ('shell-data', hashlib.sha256(DATA).hexdigest())):
        checks[path + '_digest'] = re.search(rb'(?:^|\r?\n)' + digest.encode() + rb'\s+/tmp/' + path.encode() + rb'(?:\r?\n|$)', serial) is not None
    return {'schema': 'flex-linux-bounded-shell/v1', 'source_commit': commit,
            'checks': checks, 'passed': all(checks.values()), 'busybox_sha256': DIGEST,
            'general_linux_compatibility': False, 'processes_pipes': False,
            'async_signal_delivery': False, 'physical_hardware_qualified': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', required=True)
    fetch(parser.parse_args().fetch)
