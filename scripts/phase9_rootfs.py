# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-02 first increment: isolated guest root, not live resource mounts."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_shared_maps import commands as map_commands, start as map_start

ROOT = Path(__file__).resolve().parents[1]
CASES = ('cwd', 'deny', 'fork', 'fresh')
SCRIPT = b'''set -e
/busybox mkdir -p /home/project /var/build /usr/local
printf 'int main(void){return 0;}\\n' > /home/project/main.c
/busybox cp /home/project/main.c /var/build/source
/busybox mv /var/build/source /usr/local/source
/busybox ln /usr/local/source /var/build/alias
/busybox cat /var/build/alias
echo FLEX_ROOTFS_BUSYBOX_OK
'''


def fixtures(directory, commit):
    directory = Path(directory)
    subprocess.run(['cc', *FLAGS, str(ROOT / 'tests/fixtures/compact_process_start.S'),
                    str(ROOT / 'tests/fixtures/compact_rootfs.c'), '-o', str(directory / 'rootfs.elf')],
                   check=True, capture_output=True)
    (directory / 'rootfs-script').write_bytes(SCRIPT)
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ('rootfs.elf', 'rootfs-script')}


@lru_cache(maxsize=16)
def start(commit):
    return map_start(commit) + len(map_commands(commit))


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('expected source commit')
    ops = ['hget http://10.0.2.2:8000/rootfs.elf > /tmp/rf-elf',
           'hget http://10.0.2.2:8000/rootfs-script > /tmp/rf-script',
           'sha1sum -2 256 /tmp/rf-elf', 'sha1sum -2 256 /tmp/rf-script',
           'echo FLEX_ROOTFS_BEGIN']
    for mode in CASES:
        ops.append(f'$c -r /tmp/rf-elf {mode} R_{mode}_{commit} && echo FLEX_ROOTFS_{mode}_RUN_OK')
    ops += [f'$c -r -W /tmp/rf-state /tmp/rf-elf create R_saved_{commit} && echo FLEX_ROOTFS_SAVE_OK',
            f'$c -r -R /tmp/rf-state /tmp/rf-elf reload R_saved_{commit} && echo FLEX_ROOTFS_RELOAD_OK',
            '$c -j -R /tmp/rf-state /tmp/rf-elf fresh no || echo FLEX_ROOTFS_PROFILE_DENIED',
            'echo bad > /tmp/rf-bad',
            '$c -r -R /tmp/rf-bad /tmp/rf-elf fresh no || echo FLEX_ROOTFS_CORRUPT_DENIED',
            '$c -r -b 4194304 -x /busybox=/tmp/busybox -i /tmp/rf-script /tmp/busybox ash /input && echo FLEX_ROOTFS_SHELL_RUN_OK',
            'echo FLEX_ROOTFS_END']
    first = start(commit)
    return [op + f'; echo RYZOVA_RUNTIME_STAGE_{first+i}' for i, op in enumerate(ops)] + ['echo FLEX_ROOTFS_DONE']


def inspect(serial, commit, digests):
    def line(value, body=serial):
        return re.search(rb'(?:^|\r?\n)' + re.escape(value) + rb'(?:\r?\n|$)', body) is not None
    match = re.search(rb'(?:^|\r?\n)FLEX_ROOTFS_BEGIN\r?\n(.*?)\r?\nFLEX_ROOTFS_END(?:\r?\n|$)', serial, re.S)
    body = match.group(1) if match else b''
    checks = {'section': match is not None, 'done': line(b'FLEX_ROOTFS_DONE'),
              'no_panic': re.search(rb'(?im)^panic:', serial) is None,
              'stages': all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in
                            range(start(commit), start(commit) + len(commands(commit)) - 1))}
    for name, target in (('rootfs.elf', 'rf-elf'), ('rootfs-script', 'rf-script')):
        digest = digests.get(name, '')
        checks[name] = bool(re.fullmatch('[a-f0-9]{64}', digest) and re.search(
            rb'(?:^|\r?\n)' + digest.encode() + rb'\s+/tmp/' + target.encode() + rb'(?:\r?\n|$)', serial))
    for mode in CASES:
        checks[mode] = all(line(x, body) for x in (f'FLEX_ROOTFS_OK {mode}'.encode(),
            f'R_{mode}_{commit}'.encode(), f'FLEX_ROOTFS_{mode}_RUN_OK'.encode()))
    checks['independent_reload'] = all(line(x, body) for x in (
        b'FLEX_ROOTFS_OK create', b'FLEX_ROOTFS_OK reload', b'FLEX_ROOTFS_SAVE_OK', b'FLEX_ROOTFS_RELOAD_OK')) and len(
            re.findall(rb'(?:^|\r?\n)R_saved_' + commit.encode() + rb'(?=\r?\n|$)', body)) == 2
    checks['unmodified_busybox'] = all(line(x, body) for x in (
        b'int main(void){return 0;}', b'FLEX_ROOTFS_BUSYBOX_OK', b'FLEX_ROOTFS_SHELL_RUN_OK'))
    checks['negative_imports'] = all(line(x, body) for x in (
        b'FLEX_ROOTFS_PROFILE_DENIED', b'FLEX_ROOTFS_CORRUPT_DENIED')) and len(re.findall(
            rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=1 exited=0 exit=0 steps=0 syscalls=0(?=\r?\n|$)', body)) == 2
    checks['clean_results'] = len(re.findall(
        rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)', body)) == len(CASES) + 3
    return {'schema': 'compact-linux-root-tree/v1', 'source_commit': commit, 'fixture_sha256': digests,
            'checks': checks, 'passed': all(checks.values()), 'phase_complete': False,
            'remaining': ['live-resource-mounts', 'per-application-views-and-revocation', 'mount-recovery']}
