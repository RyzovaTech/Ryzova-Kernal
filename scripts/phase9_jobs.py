# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded process groups: fork/vfork, granted exec images, wait and pipes."""
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS

ROOT=Path(__file__).resolve().parents[1]
CASES=('private','vfork','pipe','exec','vfork-exec','offset','identity','capacity','descriptions','quota','exec-quota','nonblock','wait-errors','io-quota')
DATA=b'abcdefgh\n'
SCRIPT=b'''echo FLEX_JOBS_OUTPUT
if test /probe -ef /busybox; then exit 77; fi
printf 'abc\\nxyz\\n' | /busybox grep xyz | /busybox wc -l
x=$(echo nested | /busybox cat)
printf 'value=%s\\n' "$x"
/probe private "$1" | /busybox cat
echo FLEX_JOBS_SCRIPT_OK
'''


def build(output):
    subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_jobs.c'),'-o',str(output)],check=True,capture_output=True)
    return hashlib.sha256(Path(output).read_bytes()).hexdigest()


def fixtures(directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    digest=build(directory/'jobs-fixture.elf')
    (directory/'jobs-script').write_bytes(SCRIPT);(directory/'jobs-data').write_bytes(DATA)
    return digest


def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=['hget http://10.0.2.2:8000/jobs-fixture.elf > /tmp/j-elf','sha1sum -2 256 /tmp/j-elf',
         'hget http://10.0.2.2:8000/jobs-script > /tmp/j-script','sha1sum -2 256 /tmp/j-script',
         'hget http://10.0.2.2:8000/jobs-data > /tmp/j-data','sha1sum -2 256 /tmp/j-data','cat /compact/linux/jobs','echo FLEX_JOBS_BEGIN',
         f"/amd64/bin/compact-linux -j -x /busybox -x '/probe=/tmp/j-elf' -i /tmp/j-script /tmp/busybox ash /input PJ_{commit} && echo FLEX_JOBS_RUN_OK"]
    for mode in CASES:
        grant='-i /tmp/j-data ' if mode in ('offset','identity','descriptions') else ''
        ops.append(f'/amd64/bin/compact-linux -j -x /tmp/j-elf {grant}/tmp/j-elf {mode} J_{mode}_{commit} && echo FLEX_JOB_{mode}_OK')
    ops+=['echo FLEX_JOBS_END']
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{94+i}' for i,op in enumerate(ops)]+['echo FLEX_JOBS_DONE']


def inspect(serial,commit,digest):
    def line(raw,text):return re.search(rb'(?:^|\r?\n)'+re.escape(text)+rb'(?:\r?\n|$)',raw) is not None
    section=re.search(rb'(?:^|\r?\n)FLEX_JOBS_BEGIN\r?\n(.*?)\r?\nFLEX_JOBS_END(?:\r?\n|$)',serial,re.S)
    body=section.group(1) if section else b''
    checks={'native_interface':line(serial,b'linux-amd64-static-jobs-v1'),'script':line(body,b'FLEX_JOBS_SCRIPT_OK') and line(body,b'FLEX_JOBS_RUN_OK'),
            'pipeline':line(body,b'1'), 'substitution':line(body,b'value=nested'),
            'mixed_elf':line(body,b'FLEX_JOBS_FIXTURE_OK') and line(body,('PJ_'+commit).encode()),
            'done':line(serial,b'FLEX_JOBS_DONE'),
            'stages':all(line(serial,f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(94,94+len(commands(commit))-1)),
            'no_panic':re.search(rb'(?im)^panic:',serial) is None}
    stats=rb'COMPACT_JOBS_STATS forks=([0-9]+) execs=([0-9]+) peak=([0-9]+) blocked=([0-9]+) pipebytes=([0-9]+)'
    results=re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body)
    checks['clean_results']=len(results)==1+len(CASES)
    case_stats={}
    for mode in CASES:
        proof=re.search(rb'(?:^|\r?\n)FLEX_JOBS_FIXTURE_OK\r?\n'+re.escape(f'J_{mode}_{commit}'.encode())+rb'\r?\n(.*?)\r?\nFLEX_JOB_'+re.escape(mode.encode())+rb'_OK(?:\r?\n|$)',body,re.S)
        found=re.search(rb'(?:^|\r?\n)'+stats+rb'(?:\r?\n|$)',proof.group(1)) if proof else None
        values=tuple(map(int,found.groups())) if found else None
        checks[mode]=bool(values and values[0]<=32 and values[1]<=64 and 1<=values[2]<=8 and values[4]<=4194304)
        if values:
            case_stats[mode]=dict(zip(('forks','execs','peak','blocked','pipe_bytes'),values))
            if mode=='pipe':checks['backpressure']=values[3]>0 and values[4]==81920
            if mode in ('exec','vfork-exec'):checks[mode+'_replace']=values[0]==1 and values[1]==1
            if mode in ('capacity','descriptions'):checks[mode+'_bound']=values[2]==8 and values[0]==7
            if mode=='quota':checks['fork_quota']=values[0]==32
            if mode=='exec-quota':checks['exec_quota']=values[1]==64
            if mode=='io-quota':checks['pipe_quota']=values[4]==4194304
    for path,sha in (('j-elf',digest),('j-script',hashlib.sha256(SCRIPT).hexdigest()),('j-data',hashlib.sha256(DATA).hexdigest())):
        checks[path+'_digest']=bool(re.fullmatch('[a-f0-9]{64}',sha)) and re.search(rb'(?:^|\r?\n)'+sha.encode()+rb'\s+/tmp/'+path.encode()+rb'(?:\r?\n|$)',serial) is not None
    return {'schema':'flex-linux-bounded-jobs/v1','source_commit':commit,'checks':checks,'passed':all(checks.values()),
            'cases':case_stats,'fixture_sha256':digest,'general_linux_compatibility':False,'dynamic_linker':False,
            'threads_async_signals':False,'physical_hardware_qualified':False}
