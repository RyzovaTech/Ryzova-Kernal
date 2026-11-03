# SPDX-License-Identifier: AGPL-3.0-only
"""Native qualification of invocation-local writable files and directories."""
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
ROOT=Path(__file__).resolve().parents[1]
CASES=('basic','directory','unlink','errors','shared','quota','atomic','times','grants')
SCRIPT=b'''set -e
/busybox mkdir -p /tmp/a/b
echo hello > /tmp/a/b/f
/busybox cp /tmp/a/b/f /tmp/a/b/copy
/busybox mv /tmp/a/b/copy /tmp/a/b/renamed
/busybox cat /tmp/a/b/renamed
/busybox touch /tmp/a/x
/busybox ls /tmp/a/b
/busybox rm -r /tmp/a
test ! -e /tmp/a
echo FLEX_VFS_SHELL_OK
'''

def fixtures(directory):
    directory=Path(directory)
    elf=directory/'vfs-fixture.elf'
    subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_vfs.c'),'-o',str(elf)],check=True,capture_output=True)
    (directory/'vfs-script').write_bytes(SCRIPT)
    return hashlib.sha256(elf.read_bytes()).hexdigest()

def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    ops=['hget http://10.0.2.2:8000/vfs-fixture.elf > /tmp/v-elf','sha1sum -2 256 /tmp/v-elf',
         'hget http://10.0.2.2:8000/vfs-script > /tmp/v-script','sha1sum -2 256 /tmp/v-script',
         'cat /compact/linux/filesystem','echo FLEX_VFS_BEGIN',
         '/amd64/bin/compact-linux -j -x /busybox -i /tmp/v-script /tmp/busybox ash /input && echo FLEX_VFS_SHELL_RUN_OK']
    for mode in CASES:
        grants="-x '/tmp/bound=/tmp/v-elf' " if mode=='grants' else ''
        ops.append(f'/amd64/bin/compact-linux -j -x /tmp/v-elf {grants}/tmp/v-elf /tmp/case {mode} V_{mode}_{commit} && echo FLEX_VFS_{mode}_OK')
    ops+=['echo FLEX_VFS_END']
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{119+i}' for i,op in enumerate(ops)]+['echo FLEX_VFS_DONE; echo RYZOVA_RUNTIME_STAGE_136']

def inspect(serial,commit,digest):
    def line(value):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',serial) is not None
    checks={'done':line(b'FLEX_VFS_DONE'),'metadata':line(b'linux-amd64-local-tmp-v1'),
            'script':line(b'FLEX_VFS_SHELL_OK') and line(b'FLEX_VFS_SHELL_RUN_OK'),
            'elf_hash':line((digest+' /tmp/v-elf').encode()),
            'script_hash':line((hashlib.sha256(SCRIPT).hexdigest()+' /tmp/v-script').encode()),
            'no_panic':not re.search(rb'(?im)^panic:',serial),
            'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(119,119+len(commands(commit))-1))}
    # sha1sum prints two spaces on some native versions.
    for key,sha,name in [('elf_hash',digest,'v-elf'),('script_hash',hashlib.sha256(SCRIPT).hexdigest(),'v-script')]:
        checks[key]=bool(re.search(rb'(?:^|\r?\n)'+sha.encode()+rb'\s+/tmp/'+name.encode()+rb'(?:\r?\n|$)',serial))
    for mode in CASES:checks[mode]=line(f'V_{mode}_{commit}'.encode()) and line(f'FLEX_VFS_{mode}_OK'.encode())
    match=re.search(rb'(?:^|\r?\n)FLEX_VFS_BEGIN\r?\n(.*?)\r?\nFLEX_VFS_END(?:\r?\n|$)',serial,re.S)
    checks['clean_results']=bool(match and len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',match.group(1)))==1+len(CASES))
    return {'schema':'flex-linux-local-tmp/v1','source_commit':commit,'elf_sha256':digest,'checks':checks,'passed':all(checks.values())}
