# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-03A native private-file COW qualification; not full CLX-03 acceptance."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_mounts import commands as mount_commands, start as mount_start
ROOT=Path(__file__).resolve().parents[1]
CASES=('basic','readonly','fork','clean-fork','page-granularity','offset','mixed','io','unlink','release','bus','tail','fixed','futex','exec','quota')


def fixtures(directory,commit):
    path=Path(directory)/'private-maps.elf'
    subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_private_maps.c'),'-o',str(path)],check=True,capture_output=True)
    return {'private-maps.elf':hashlib.sha256(path.read_bytes()).hexdigest()}


@lru_cache(maxsize=16)
def start(commit):
    return mount_start(commit)+len(mount_commands(commit))


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=['hget http://10.0.2.2:8000/private-maps.elf > /tmp/pr-elf','sha1sum -2 256 /tmp/pr-elf',
         'p=/tmp/pr-elf; o=/tmp/private','echo FLEX_PRIVATE_BEGIN']
    for mode in CASES:
        ops.append(f'$c -j -x $p $p $o {mode} C_{mode}_{commit} && echo FLEX_PRIVATE_{mode}_RUN_OK')
    ops += [f'$c -j -W /tmp/pr-state $p $o create C_saved_{commit} && echo FLEX_PRIVATE_SAVE_OK',
            f'$c -j -R /tmp/pr-state $p $o reload C_saved_{commit} && echo FLEX_PRIVATE_RELOAD_OK','echo FLEX_PRIVATE_END']
    first=start(commit)
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{first+i}' for i,op in enumerate(ops)]+['echo FLEX_PRIVATE_DONE']


def inspect(serial,commit,digests):
    def line(value,body=serial):
        return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
    match=re.search(rb'(?:^|\r?\n)FLEX_PRIVATE_BEGIN\r?\n(.*?)\r?\nFLEX_PRIVATE_END(?:\r?\n|$)',serial,re.S)
    body=match.group(1) if match else b''
    checks={'section':match is not None,'done':line(b'FLEX_PRIVATE_DONE'),
            'no_panic':re.search(rb'(?im)^panic:',serial) is None,
            'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1))}
    digest=digests.get('private-maps.elf','')
    checks['fixture_digest']=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/pr-elf(?:\r?\n|$)',serial))
    for mode in CASES:
        checks[mode]=all(line(x,body) for x in (f'FLEX_PRIVATE_OK {mode}'.encode(),f'C_{mode}_{commit}'.encode(),f'FLEX_PRIVATE_{mode}_RUN_OK'.encode()))
    checks['private_data_not_persisted']=all(line(x,body) for x in (b'FLEX_PRIVATE_OK create',b'FLEX_PRIVATE_OK reload',b'FLEX_PRIVATE_SAVE_OK',b'FLEX_PRIVATE_RELOAD_OK')) and len(re.findall(rb'(?:^|\r?\n)C_saved_'+commit.encode()+rb'(?=\r?\n|$)',body))==2
    checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)+2
    return {'schema':'compact-linux-private-file-maps/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values()),
            'phase_complete':False,'increment':'CLX-03A','remaining':['shared-anonymous-memory-and-futex','process-session-APIs','measured-target-and-aggregate-budgets'],'v1_complete':False}
