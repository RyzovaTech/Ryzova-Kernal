# SPDX-License-Identifier: AGPL-3.0-only
"""Native Plan 9 TCP-resource qualification, distinct from host reference I/O."""
import hashlib
from pathlib import Path
import re
import shutil
from phase9_dynamic import build
from phase9_persistence import commands as persistence_commands,start as persistence_start
ROOT=Path(__file__).resolve().parents[1]
CASES=('http','poll','peek','msg-peek','nonblock','fork','duplicate','denied')
def fixtures(directory,commit):
    directory=Path(directory);cache=ROOT/'artifacts/musl-fixtures';build(cache);shutil.copy2(cache/'external-http',directory/'external-http')
    (directory/'external-probe.txt').write_text('FLEX_EXTERNAL_SOURCE_'+commit+'\n')
    (directory/'external-stall.txt').write_text('FLEX_EXTERNAL_SOURCE_'+commit+'\n')
    (directory/'external-hosts').write_text('10.20.30.40 resource.flex.test\n')
    return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('external-http','external-hosts')}
def start(commit):return persistence_start(commit)+len(persistence_commands(commit))
def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=['hget http://10.0.2.2:8000/external-http > /tmp/ex-http','sha1sum -2 256 /tmp/ex-http','hget http://10.0.2.2:8000/external-hosts > /tmp/ex-hosts','sha1sum -2 256 /tmp/ex-hosts','cat /compact/linux/network',
         f"g=(-n '10.20.30.40:8080=tcp!10.0.2.2!8000'); e=/tmp/ex-http; k=FLEX_EXTERNAL_SOURCE_{commit}",'u=http://10.20.30.40:8080/external-probe.txt',
         "h=(-x '/etc/hosts=/tmp/ex-hosts'); v=http://resource.flex.test:8080/external-probe.txt",'echo FLEX_EXTERNAL_BEGIN']
    for mode in CASES:ops.append(f'$c -j -b 4194304 $l $g $e {mode} $k E_{mode}_{commit} && echo FLEX_EXTERNAL_{mode}_RUN_OK')
    ops += ['$c -j -b 4194304 $g /tmp/busybox wget -Y off -q -O - $u && echo FLEX_EXTERNAL_WGET_OK',
            '$c -j -b 4194304 $g -W /tmp/ex-state /tmp/busybox wget -Y off -q -O /tmp/download $u && echo FLEX_EXTERNAL_WGET_SAVE_OK',
            '$c -j -R /tmp/ex-state /tmp/busybox cat /tmp/download && echo FLEX_EXTERNAL_WGET_RELOAD_OK',
            '$c -j -b 4194304 $g $h /tmp/busybox wget -Y off -q -O - $v && echo FLEX_EXTERNAL_NAMED_OK',
            f'$c -j -t 5000 -b 4194304 $l $g $e timeout $k E_timeout_{commit} || echo FLEX_EXTERNAL_DEADLINE_DENIED',f'$c -j -b 4194304 $l $e http $k E_nogrant_{commit} || echo FLEX_EXTERNAL_UNGRANTED_DENIED','echo FLEX_EXTERNAL_END']
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{start(commit)+i}' for i,op in enumerate(ops)]+['echo FLEX_EXTERNAL_DONE']
def inspect(serial,commit,digests,host_requests,host_stall_requests):
    def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
    match=re.search(rb'(?:^|\r?\n)FLEX_EXTERNAL_BEGIN\r?\n(.*?)\r?\nFLEX_EXTERNAL_END(?:\r?\n|$)',serial,re.S);body=match.group(1) if match else b''
    digest=digests.get('external-http','')
    checks={'section':match is not None,'metadata':line(b'linux-amd64-tcp-resources-v1'),'done':line(b'FLEX_EXTERNAL_DONE'),'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1)),
            'fixture_hash':bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/ex-http(?:\r?\n|$)',serial)),'actual_native_http_requests':host_requests==len(CASES)+2,'no_panic':re.search(rb'(?im)^panic:',serial) is None}
    hosts_digest=digests.get('external-hosts','')
    checks['hosts_hash']=bool(re.fullmatch('[a-f0-9]{64}',hosts_digest) and re.search(rb'(?:^|\r?\n)'+hosts_digest.encode()+rb'\s+/tmp/ex-hosts(?:\r?\n|$)',serial))
    for mode in CASES:checks[mode]=all(line(x,body) for x in (f'FLEX_EXTERNAL_OK {mode}'.encode(),f'E_{mode}_{commit}'.encode(),f'FLEX_EXTERNAL_{mode}_RUN_OK'.encode()))
    checks['unmodified_wget']=all(line(value,body) for value in (b'FLEX_EXTERNAL_WGET_OK',b'FLEX_EXTERNAL_WGET_SAVE_OK',b'FLEX_EXTERNAL_WGET_RELOAD_OK',b'FLEX_EXTERNAL_NAMED_OK')) and len(re.findall(rb'(?:^|\r?\n)FLEX_EXTERNAL_SOURCE_'+commit.encode()+rb'(?=\r?\n|$)',body))==3
    checks['deadline_denied']=line(b'FLEX_EXTERNAL_DEADLINE_DENIED',body) and host_stall_requests==1 and re.search(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=11 exited=[01] exit=[0-9]+ steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?:\r?\n|$)',body) is not None
    checks['no_grant_denied']=line(b'FLEX_EXTERNAL_UNGRANTED_DENIED',body) and re.search(rb'(?:^|\r?\n)EXTERNAL_HTTP_FAILED line=[0-9]+ errno=101(?:\r?\n|$)',body) is not None
    checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)+4
    return {'schema':'flex-linux-tcp-resources/v1','source_commit':commit,'fixture_sha256':digests,'native_http_requests':host_requests,'native_stall_requests':host_stall_requests,'checks':checks,'passed':all(checks.values())}
