# SPDX-License-Identifier: AGPL-3.0-only
"""Qualify cooperative Linux threads inside the source-built native kernel."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from phase9_process import FLAGS
from phase9_dynamic import build
from phase9_runtime import commands as runtime_commands
ROOT=Path(__file__).resolve().parents[1]
PTHREADS=('basic','fds','fs','cond','robust','detach','cancel','kill','fork','exec','exec-failed','capacity','quota')
RAW=('leader-exit','exit-group','robust','futex','clock-ceiling','entropy-quota')
NAMES={'thread-fixture':'th-elf','compact_thread_lifetime':'th-raw','compact_mm_lifetime':'th-mm'}

def fixtures(directory,commit):
    directory=Path(directory);cache=ROOT/'artifacts/musl-fixtures';build(cache)
    shutil.copy2(cache/'thread-fixture',directory/'thread-fixture')
    for name in ('compact_thread_lifetime','compact_mm_lifetime'):
        subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/f'tests/fixtures/{name}.c'),'-o',str(directory/name)],check=True,capture_output=True)
    return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in NAMES}

def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=[]
    for name,target in NAMES.items():ops += [f'hget http://10.0.2.2:8000/{name} > /tmp/{target}',f'sha1sum -2 256 /tmp/{target}']
    ops += ['cat /compact/linux/threads','echo FLEX_THREADS_BEGIN']
    for mode in PTHREADS:
        ops.append(f"$c -j -b 4194304 $l -x '/tmp/th-elf=/tmp/th-elf' /tmp/th-elf {mode} /tmp T_{mode}_{commit} && echo FLEX_PTHREAD_{mode}_OK")
    for mode in RAW:
        ops.append(f'$c -j /tmp/th-raw {mode} T_{mode}_{commit} && echo FLEX_RAW_{mode}_OK')
    ops += [f'$c -j /tmp/th-mm T_mm_{commit} && echo FLEX_MM_RUN_OK','echo FLEX_THREADS_END']
    start=137+len(runtime_commands(commit))
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{start+i}' for i,op in enumerate(ops)]+['echo FLEX_THREADS_DONE']

def inspect(serial,commit,digests):
    def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
    match=re.search(rb'(?:^|\r?\n)FLEX_THREADS_BEGIN\r?\n(.*?)\r?\nFLEX_THREADS_END(?:\r?\n|$)',serial,re.S)
    body=match.group(1) if match else b''
    start=137+len(runtime_commands(commit))
    checks={'section':match is not None,'metadata':line(b'linux-amd64-threads-v1'),'done':line(b'FLEX_THREADS_DONE'),
            'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start,start+len(commands(commit))-1)),
            'no_panic':re.search(rb'(?im)^panic:',serial) is None}
    for name,target in NAMES.items():
        digest=digests.get(name,'')
        checks['hash_'+target]=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/'+target.encode()+rb'(?:\r?\n|$)',serial))
    for mode in PTHREADS:
        checks['pthread_'+mode]=all(line(x,body) for x in (f'FLEX_THREADS_OK {mode}'.encode(),f'T_{mode}_{commit}'.encode(),f'FLEX_PTHREAD_{mode}_OK'.encode()))
    for mode in RAW:
        checks['raw_'+mode]=all(line(x,body) for x in (f'FLEX_RAW_THREADS_OK {mode}'.encode(),f'T_{mode}_{commit}'.encode(),f'FLEX_RAW_{mode}_OK'.encode()))
    checks['mm_lifetime']=all(line(x,body) for x in (b'FLEX_MM_LIFETIME_OK',f'T_mm_{commit}'.encode(),b'FLEX_MM_RUN_OK'))
    checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(PTHREADS)+len(RAW)+1
    return {'schema':'flex-linux-threads/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
