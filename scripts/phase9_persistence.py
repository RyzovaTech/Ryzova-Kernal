# SPDX-License-Identifier: AGPL-3.0-only
"""Source-built native qualification for explicit immutable filesystem snapshots."""
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_sockets import commands as socket_commands,start as socket_start
ROOT=Path(__file__).resolve().parents[1]
def fixtures(directory,commit):
    path=Path(directory)/'persistence.elf'
    subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_persistence.c'),'-o',str(path)],check=True,capture_output=True)
    return {'persistence.elf':hashlib.sha256(path.read_bytes()).hexdigest()}
def start(commit):return socket_start(commit)+len(socket_commands(commit))
def commands(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    token='P_'+commit
    ops=['hget http://10.0.2.2:8000/persistence.elf > /tmp/ps-elf','sha1sum -2 256 /tmp/ps-elf','cat /compact/linux/persistence','echo FLEX_PERSISTENCE_BEGIN',
         f'$c -j -W /tmp/ps-one /tmp/ps-elf create {token} && echo FLEX_PERSIST_CREATE_OK',
         f'$c -j -R /tmp/ps-one /tmp/ps-elf verify {token} && echo FLEX_PERSIST_VERIFY_OK',
         f'$c -j -R /tmp/ps-one -W /tmp/ps-two /tmp/ps-elf append {token} && echo FLEX_PERSIST_APPEND_OK',
         f"$c -j -R /tmp/ps-two /tmp/ps-elf verify '{token}!' && echo FLEX_PERSIST_APPENDED_OK",
         f'$c -j -R /tmp/ps-two -W /tmp/ps-three /tmp/ps-elf rename {token} && echo FLEX_PERSIST_RENAME_OK',
         f'$c -j -R /tmp/ps-three /tmp/ps-elf empty {token} && echo FLEX_PERSIST_EMPTY_OK',
         'cp /tmp/ps-one /tmp/ps-bad; echo invalid > /tmp/ps-bad',
         f'$c -j -R /tmp/ps-bad /tmp/ps-elf empty {token} || echo FLEX_PERSIST_CORRUPT_DENIED',
         'echo FLEX_PERSISTENCE_END']
    return [op+f'; echo RYZOVA_RUNTIME_STAGE_{start(commit)+i}' for i,op in enumerate(ops)]+['echo FLEX_PERSISTENCE_DONE']
def inspect(serial,commit,digests):
    def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
    match=re.search(rb'(?:^|\r?\n)FLEX_PERSISTENCE_BEGIN\r?\n(.*?)\r?\nFLEX_PERSISTENCE_END(?:\r?\n|$)',serial,re.S);body=match.group(1) if match else b''
    digest=digests.get('persistence.elf','')
    checks={'section':match is not None,'metadata':line(b'linux-amd64-filesystem-snapshot-v1'),'done':line(b'FLEX_PERSISTENCE_DONE'),'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1)),'fixture_hash':bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/ps-elf(?:\r?\n|$)',serial)),'challenge':line(('P_'+commit).encode(),body),'append_challenge':line(('P_'+commit+'!').encode(),body),'no_panic':re.search(rb'(?im)^panic:',serial) is None}
    for mode in ('create','verify','append','rename','empty'):checks[mode]=line(f'FLEX_PERSISTENCE_OK {mode}'.encode(),body)
    for mode in ('CREATE','VERIFY','APPEND','APPENDED','RENAME','EMPTY'):checks['run_'+mode]=line(f'FLEX_PERSIST_{mode}_OK'.encode(),body)
    checks['challenge_count']=len(re.findall(rb'(?:^|\r?\n)P_'+commit.encode()+rb'(?=\r?\n|$)',body))==5
    checks['corruption_rejected']=line(b'FLEX_PERSIST_CORRUPT_DENIED',body) and line(b'COMPACT_LINUX_RESULT status=1 exited=0 exit=0 steps=0 syscalls=0',body)
    checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==6
    return {'schema':'flex-linux-filesystem-snapshot/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
