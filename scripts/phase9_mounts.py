# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-02 native filesystem/resource-view acceptance, bounded profiles only."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_rootfs import commands as root_commands, start as root_start
ROOT = Path(__file__).resolve().parents[1]
CASES = ('readonly', 'views', 'hidden', 'denials', 'lifetime', 'sync', 'rename-failure')
SCRIPT = b'''set -e
/busybox mkdir -p /home/share/shell
printf 'int main(void){return 0;}\\n' > /home/share/shell/main.c
/busybox cp /home/share/shell/main.c /home/share/shell/copy.c
/busybox mv /home/share/shell/copy.c /home/share/shell/source.c
/busybox cat /home/share/shell/source.c
echo FLEX_MOUNT_BUSYBOX_OK
'''


def fixtures(directory, commit):
    directory = Path(directory)
    subprocess.run(['cc', *FLAGS, str(ROOT / 'tests/fixtures/compact_process_start.S'),
                    str(ROOT / 'tests/fixtures/compact_mounts.c'), '-o', str(directory / 'mounts.elf')],
                   check=True, capture_output=True)
    (directory / 'mounts-script').write_bytes(SCRIPT)
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ('mounts.elf', 'mounts-script')}


@lru_cache(maxsize=16)
def start(commit):
    return root_start(commit) + len(root_commands(commit))


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('expected source commit')
    ops = ['hget http://10.0.2.2:8000/mounts.elf > /tmp/mt-elf',
           'hget http://10.0.2.2:8000/mounts-script > /tmp/mt-script',
           'sha1sum -2 256 /tmp/mt-elf', 'sha1sum -2 256 /tmp/mt-script',
           'mkdir -p /tmp/mt-data /tmp/mt-admin /tmp/mt-quota',
           "g=(-M 'rw:/home/share=/tmp/mt-data'); r=(-M 'r:/home/share=/tmp/mt-data'); m=/tmp/mt-elf",
           'echo FLEX_MOUNTS_BEGIN',
           f'$c -r $g -W /tmp/mt-state $m create Q_saved_{commit} && echo FLEX_MOUNT_SAVE_OK',
           f'echo -n Q_saved_{commit} > /tmp/mt-expected',
           'cmp /tmp/mt-data/project/source.c /tmp/mt-expected && echo FLEX_MOUNT_HOST_DATA_OK',
           f'$c -r -R /tmp/mt-state $m absent Q_absent_{commit} && echo FLEX_MOUNT_ABSENT_RUN_OK']
    for mode in CASES:
        ops.append(f'$c -r '+('$r' if mode == 'readonly' else '$g')+f' $m {mode} Q_saved_{commit} && echo FLEX_MOUNT_{mode}_RUN_OK')
    ops += [f'$c -r $g -x /worker -x /privileged -A /worker:1:0 -A /privileged:1:1 $m exec Q_saved_{commit} && echo FLEX_MOUNT_EXEC_RUN_OK',
            f"$c -r $g -A '@entry:1:0' $m readonly Q_saved_{commit} && echo FLEX_MOUNT_ENTRY_RUN_OK",
            f'$c -r $g -R /tmp/mt-state $m reload Q_saved_{commit} && echo FLEX_MOUNT_RESTART_RUN_OK',
            f'$c -r $g $m check Q_saved_{commit} && echo FLEX_MOUNT_CHECK_RUN_OK',
            "g=(-M 'rw:/home/share=/tmp/mt-quota')",
            f'$c -r $g $m quota Q_quota_{commit} && echo FLEX_MOUNT_QUOTA_RUN_OK',
            "g=(-M 'rw:/home/share=/tmp/mt-data')",
            f'$c -r $g -b 2000 $m fault Q_fault_{commit} || echo FLEX_MOUNT_LIMIT_OK',
            f'echo -n Q_fault_{commit} > /tmp/mt-expected',
            'cmp /tmp/mt-data/completed /tmp/mt-expected && echo FLEX_MOUNT_RECOVERY_OK',
            '$c -r $g -b 4194304 -x /busybox -i /tmp/mt-script /tmp/busybox ash /input && echo FLEX_MOUNT_BUSYBOX_RUN_OK',
            'echo 1 > /tmp/mt-admin/token',
            "a=(-M 'rw:/var/admin=/tmp/mt-admin' -K /tmp/mt-admin/token)",
            f'$c -r $g $a $m revocation Q_revoke_{commit} && echo FLEX_MOUNT_REVOKE_RUN_OK',
            'echo FLEX_MOUNTS_END']
    first = start(commit)
    return [op + f'; echo RYZOVA_RUNTIME_STAGE_{first+i}' for i, op in enumerate(ops)] + ['echo FLEX_MOUNTS_DONE']


def inspect(serial, commit, digests):
    def line(value, body=serial):
        return re.search(rb'(?:^|\r?\n)' + re.escape(value) + rb'(?:\r?\n|$)', body) is not None
    match = re.search(rb'(?:^|\r?\n)FLEX_MOUNTS_BEGIN\r?\n(.*?)\r?\nFLEX_MOUNTS_END(?:\r?\n|$)', serial, re.S)
    body = match.group(1) if match else b''
    checks = {'section': match is not None, 'done': line(b'FLEX_MOUNTS_DONE'),
              'no_panic': re.search(rb'(?im)^panic:', serial) is None,
              'stages': all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in
                            range(start(commit), start(commit)+len(commands(commit))-1))}
    for name, target in (('mounts.elf', 'mt-elf'), ('mounts-script', 'mt-script')):
        digest = digests.get(name, '')
        checks[name] = bool(re.fullmatch('[a-f0-9]{64}', digest) and re.search(
            rb'(?:^|\r?\n)' + digest.encode() + rb'\s+/tmp/' + target.encode() + rb'(?:\r?\n|$)', serial))
    for mode in CASES:
        checks[mode] = all(line(x, body) for x in (f'FLEX_MOUNT_OK {mode}'.encode(),
            f'FLEX_MOUNT_{mode}_RUN_OK'.encode()))
    for key, marker in (('create', 'SAVE'), ('absent', 'ABSENT_RUN'), ('again', 'EXEC_RUN'),
                        ('reload', 'RESTART_RUN'), ('check', 'CHECK_RUN'), ('quota', 'QUOTA_RUN'), ('revocation', 'REVOKE_RUN')):
        checks[key] = line(f'FLEX_MOUNT_OK {key}'.encode(), body) and line(f'FLEX_MOUNT_{marker}_OK'.encode(), body)
    checks['entry_view'] = line(b'FLEX_MOUNT_ENTRY_RUN_OK', body)
    checks['host_live_data'] = line(b'FLEX_MOUNT_HOST_DATA_OK', body)
    checks['fault_recovery'] = all(line(x, body) for x in (b'FLEX_MOUNT_LIMIT_OK', b'FLEX_MOUNT_RECOVERY_OK')) and re.search(
        rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=4 exited=0 exit=0 steps=2000 syscalls=[1-9][0-9]*(?=\r?\n|$)', body) is not None
    checks['unmodified_busybox'] = all(line(x, body) for x in (b'int main(void){return 0;}', b'FLEX_MOUNT_BUSYBOX_OK', b'FLEX_MOUNT_BUSYBOX_RUN_OK'))
    checks['saved_challenge_count'] = len(re.findall(rb'(?:^|\r?\n)Q_saved_' + commit.encode() + rb'(?=\r?\n|$)', body)) == len(CASES)+5
    checks['challenges'] = all(line(f'Q_{mode}_{commit}'.encode(), body) for mode in ('saved', 'absent', 'quota', 'revoke'))
    checks['clean_results'] = len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)', body)) == len(CASES)+9
    return {'schema': 'compact-linux-resource-mounts/v1', 'source_commit': commit, 'fixture_sha256': digests,
            'checks': checks, 'passed': all(checks.values()), 'acceptance': ['FS-ROOT','FS-ISOLATION','FS-PERSIST'],
            'v1_complete': False, 'profile': 'bounded-root-and-directory-capabilities',
            'not_qualified': ['general-posix-on-9p','power-loss-durability','V1-application-targets','ARM64-hardware']}
