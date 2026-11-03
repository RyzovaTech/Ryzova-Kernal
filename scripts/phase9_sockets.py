# SPDX-License-Identifier: AGPL-3.0-only
"""Native gate for invocation-local socket and HTTP application execution."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from phase9_process import FLAGS
from phase9_dynamic import build
from phase9_threads import commands as thread_commands
from phase9_runtime import commands as runtime_commands
ROOT=Path(__file__).resolve().parents[1]
CASES=('pair','unix','inet','accept-fault','peek','poll','shutdown','sigpipe','nonblock','alias','reclaim','backpressure','bound','errors','fd-limit','namespace','poll-timeout','poll-wake','message','options','accept4','byte-order','bad-message','wrap','traffic-quota','queue-close')
DIFFERENTIAL=('pair','inet','peek','poll','shutdown','sigpipe','nonblock','alias','reclaim','bound','poll-timeout','poll-wake','message','options','accept4','byte-order','bad-message','wrap')
NAMES={'sockets.elf':'sk-raw','socket-http':'sk-http'}
def fixtures(directory,commit):
    directory=Path(directory);cache=ROOT/'artifacts/musl-fixtures';build(cache)
    subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_sockets.c'),'-o',str(directory/'sockets.elf')],check=True,capture_output=True)
    shutil.copy2(cache/'socket-http',directory/'socket-http')
    return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in NAMES}
def start(commit):return 137+len(runtime_commands(commit))+len(thread_commands(commit))
def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=[]
    for name,target in NAMES.items():ops += [f'hget http://10.0.2.2:8000/{name} > /tmp/{target}',f'sha1sum -2 256 /tmp/{target}']
    ops += ['cat /compact/linux/sockets','echo FLEX_SOCKETS_BEGIN']
    for mode in CASES:ops.append(f'$c -j /tmp/sk-raw {mode} N_{mode}_{commit} && echo FLEX_SOCKET_{mode}_OK')
    ops += [f'$c -j -b 4194304 $l /tmp/sk-http H_{commit} && echo FLEX_HTTP_RUN_OK','echo FLEX_SOCKETS_END']
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{start(commit)+i}' for i,op in enumerate(ops)]+['echo FLEX_SOCKETS_DONE']
def inspect(serial,commit,digests):
    def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
    match=re.search(rb'(?:^|\r?\n)FLEX_SOCKETS_BEGIN\r?\n(.*?)\r?\nFLEX_SOCKETS_END(?:\r?\n|$)',serial,re.S)
    body=match.group(1) if match else b''
    checks={'section':match is not None,'metadata':line(b'linux-amd64-local-sockets-v1'),'done':line(b'FLEX_SOCKETS_DONE'),'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1)),'no_panic':re.search(rb'(?im)^panic:',serial) is None}
    for name,target in NAMES.items():
        digest=digests.get(name,'');checks['hash_'+target]=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/'+target.encode()+rb'(?:\r?\n|$)',serial))
    for mode in CASES:checks[mode]=all(line(x,body) for x in (f'FLEX_SOCKETS_OK {mode}'.encode(),f'N_{mode}_{commit}'.encode(),f'FLEX_SOCKET_{mode}_OK'.encode()))
    checks['http']=all(line(x,body) for x in (b'FLEX_SOCKET_HTTP_OK',f'H_{commit}'.encode(),b'FLEX_HTTP_RUN_OK'))
    checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)+1
    return {'schema':'flex-linux-local-sockets/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
