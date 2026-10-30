# SPDX-License-Identifier: AGPL-3.0-only
"""Native qualification for real guest signal frames and musl dynamic linking."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from phase9_process import FLAGS
from phase9_dynamic import build as build_dynamic
from phase9_compiler import build as build_compiler,source as compiler_source
ROOT=Path(__file__).resolve().parents[1]
SIGNALS=('handler','mask','nested','restart','eintr','alternate','stop','fatal','bad-frame','realtime','no-zombie','vector','nodefer','reset','tkill','rt-quota','sleep','timer','alarm','sigwait')
NAMES={'signals.elf':'s-elf','runtime-script':'r-script','musl-libc.so':'l-lib','libflex.so':'l-so','dynamic-hello':'l-hello','dynamic-dlopen':'l-open','dynamic-needed':'l-need','dynamic-memory':'l-mem','tcc-fixture':'tcc','compiler-source':'c-src'}
SCRIPT=b'''(exit 7) &
p=$!
wait "$p"
test "$?" = 7 || exit 73
trap 'echo FLEX_TRAP_OK' USR1
kill -USR1 $$
echo FLEX_BACKGROUND_OK
echo "$1"
'''

def fixtures(directory,commit):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_signals.c'),'-o',str(directory/'signals.elf')],check=True,capture_output=True)
    (directory/'runtime-script').write_bytes(SCRIPT)
    cache=ROOT/'artifacts/musl-fixtures';build_compiler(cache)
    (directory/'compiler-source').write_bytes(compiler_source(commit))
    for name in NAMES:
        if name not in ('signals.elf','runtime-script','compiler-source'):shutil.copy2(cache/name,directory/name)
    return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in NAMES}

def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=[]
    for name,target in NAMES.items():ops += [f'hget http://10.0.2.2:8000/{name} > /tmp/{target}',f'sha1sum -2 256 /tmp/{target}']
    ops += ['cat /compact/linux/runtime','echo FLEX_RUNTIME_BEGIN',f'/amd64/bin/compact-linux -j -i /tmp/r-script /tmp/busybox ash /input R_{commit} && echo FLEX_BACKGROUND_RUN_OK']
    for mode in SIGNALS:ops.append(f'/amd64/bin/compact-linux -j /tmp/s-elf {mode} S_{mode}_{commit} && echo FLEX_SIGNAL_{mode}_OK')
    interp="-x '/lib/ld-musl-x86_64.so.1=/tmp/l-lib'"
    lib="-x '/lib/libflex.so=/tmp/l-so'"
    ops += [f'/amd64/bin/compact-linux -j {interp} /tmp/l-hello D_{commit} && echo FLEX_DYNAMIC_HELLO_OK',
            f'/amd64/bin/compact-linux -j {interp} {lib} /tmp/l-open && echo FLEX_DYNAMIC_OPEN_OK',
            f'/amd64/bin/compact-linux -j {interp} {lib} /tmp/l-need && echo FLEX_DYNAMIC_NEEDED_OK',
            f"/amd64/bin/compact-linux -j -x '/library=/tmp/l-so' /tmp/l-mem M_{commit} && echo FLEX_DYNAMIC_MEMORY_OK",
            "c=/amd64/bin/compact-linux; l=(-x '/lib/ld-musl-x86_64.so.1=/tmp/l-lib')",
            '$c -j -b 4194304 $l -i /tmp/c-src /tmp/tcc -nostdinc -nostdlib -static -o /output -x c /input > /tmp/k-elf && echo FLEX_COMPILER_OK',
            '$c -j /tmp/k-elf && echo FLEX_COMPILED_EXEC_OK',
            'echo FLEX_RUNTIME_END']
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{137+i}' for i,op in enumerate(ops)]+['echo FLEX_RUNTIME_DONE']

def inspect(serial,commit,digests):
    def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
    match=re.search(rb'(?:^|\r?\n)FLEX_RUNTIME_BEGIN\r?\n(.*?)\r?\nFLEX_RUNTIME_END(?:\r?\n|$)',serial,re.S)
    body=match.group(1) if match else b''
    checks={'section':match is not None,'metadata':line(b'linux-amd64-runtime-v1'),'done':line(b'FLEX_RUNTIME_DONE'),
            'background':all(line(x,body) for x in (b'FLEX_TRAP_OK',b'FLEX_BACKGROUND_OK',b'FLEX_BACKGROUND_RUN_OK',f'R_{commit}'.encode())),
            'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(137,137+len(commands(commit))-1)),
            'no_panic':re.search(rb'(?im)^panic:',serial) is None}
    for name,target in NAMES.items():
        digest=digests.get(name,'')
        checks['hash_'+target]=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/'+target.encode()+rb'(?:\r?\n|$)',serial))
    for mode in SIGNALS:checks['signal_'+mode]=all(line(x,body) for x in (b'FLEX_SIGNALS_OK',f'S_{mode}_{commit}'.encode(),f'FLEX_SIGNAL_{mode}_OK'.encode()))
    checks['hello']=line(f'FLEX_DYNAMIC_OK 7 D_{commit}'.encode(),body) and line(b'FLEX_DYNAMIC_HELLO_OK',body)
    checks['dlopen']=line(b'FLEX_DLOPEN_OK 29',body) and line(b'FLEX_DYNAMIC_OPEN_OK',body)
    checks['needed']=line(b'FLEX_NEEDED_OK 29',body) and line(b'FLEX_DYNAMIC_NEEDED_OK',body)
    checks['memory']=line(b'FLEX_MEMORY_OK',body) and line(f'M_{commit}'.encode(),body) and line(b'FLEX_DYNAMIC_MEMORY_OK',body)
    checks['compiler']=line(b'FLEX_COMPILER_OK',body) and line(b'FLEX_COMPILED_EXEC_OK',body) and line(b'FLEX_COMPILED_IN_GUEST',body) and line(f'C_{commit}'.encode(),body)
    checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(SIGNALS)+7
    return {'schema':'flex-linux-runtime/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
