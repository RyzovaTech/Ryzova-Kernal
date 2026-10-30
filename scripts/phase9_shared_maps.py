# SPDX-License-Identifier: AGPL-3.0-only
"""Source-built native shared file mapping, SIGBUS and persistence qualification."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from phase9_process import FLAGS
from phase9_dynamic import build
from phase9_hardlinks import commands as hardlink_commands,start as hardlink_start
ROOT=Path(__file__).resolve().parents[1]
CASES=('basic','fork','unlink','tail','bus','bus-handler','bus-context','bus-flags','offset','fixed','io','exec','exec-cycle','syscall-fault','bus-blocked','errors','release','permissions','quota','output-alias','futex-policy')
def fixtures(directory,commit):
 directory=Path(directory);cache=ROOT/'artifacts/musl-fixtures';build(cache);shutil.copy2(cache/'shared-map-app',directory/'shared-map-app')
 subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_shared_maps.c'),'-o',str(directory/'shared-maps.elf')],check=True,capture_output=True)
 return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('shared-maps.elf','shared-map-app')}
@lru_cache(maxsize=16)
def start(commit):return hardlink_start(commit)+len(hardlink_commands(commit))
def commands(commit):
 if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
 ops=['hget http://10.0.2.2:8000/shared-maps.elf > /tmp/mm-elf','sha1sum -2 256 /tmp/mm-elf','hget http://10.0.2.2:8000/shared-map-app > /tmp/mm-app','sha1sum -2 256 /tmp/mm-app','cat /compact/linux/runtime','m=/tmp/mm-elf; o=/tmp/links','echo FLEX_MAP_BEGIN']
 for mode in CASES:ops.append(f'$c -j -x $m $m $o {mode} M_{mode}_{commit} && echo FLEX_MAP_{mode}_RUN_OK')
 ops += [f'$c -j -W /tmp/mm-state $m $o create M_saved_{commit} && echo FLEX_MAP_SAVE_OK',f'$c -j -R /tmp/mm-state $m $o reload M_saved_{commit} && echo FLEX_MAP_RELOAD_OK',f'$c -j -b 4194304 $l -W /tmp/mm-musl /tmp/mm-app /tmp/map-app M_musl_{commit} && echo FLEX_MAP_MUSL_RUN_OK','$c -j -R /tmp/mm-musl /tmp/busybox head -c 17 /tmp/map-app/file && echo FLEX_MAP_BUSYBOX_OK',f'$c -j -b 10000 -W /tmp/mm-fault $m $o fault M_fault_{commit} || echo FLEX_MAP_LIMIT_OK',f'$c -j -R /tmp/mm-fault $m $o fault-reload M_fault_{commit} && echo FLEX_MAP_FAULT_RELOAD_OK','echo FLEX_MAP_END']
 first=start(commit)
 return [op+f'; echo RYZOVA_RUNTIME_STAGE_{first+i}' for i,op in enumerate(ops)]+['echo FLEX_MAP_DONE']
def inspect(serial,commit,digests):
 def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
 match=re.search(rb'(?:^|\r?\n)FLEX_MAP_BEGIN\r?\n(.*?)\r?\nFLEX_MAP_END(?:\r?\n|$)',serial,re.S);body=match.group(1) if match else b''
 checks={'section':match is not None,'done':line(b'FLEX_MAP_DONE'),'discovery':line(b'memory=shared-guest-files shared-file-pages=64 sync=instruction-and-syscall-boundaries bus=guest-SIGBUS',serial),'no_panic':re.search(rb'(?im)^panic:',serial) is None,'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1))}
 for name,target in (('shared-maps.elf','mm-elf'),('shared-map-app','mm-app')):
  digest=digests.get(name,'');checks[name]=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/'+target.encode()+rb'(?:\r?\n|$)',serial))
 for mode in CASES:checks[mode]=all(line(x,body) for x in (f'FLEX_MAP_OK {mode}'.encode(),f'M_{mode}_{commit}'.encode(),f'FLEX_MAP_{mode}_RUN_OK'.encode()))
 checks['saved_mapped_data']=all(line(x,body) for x in (b'FLEX_MAP_OK create',b'FLEX_MAP_OK reload',b'FLEX_MAP_SAVE_OK',b'FLEX_MAP_RELOAD_OK')) and len(re.findall(rb'(?:^|\r?\n)M_saved_'+commit.encode()+rb'(?=\r?\n|$)',body))==2
 checks['musl_pthreads_and_fork']=all(line(x,body) for x in (b'FLEX_MAP_MUSL_OK',f'M_musl_{commit}'.encode(),b'FLEX_MAP_MUSL_RUN_OK'))
 checks['unmodified_busybox']=line(b'FLEX_MAPPED_FILE',body) and line(b'FLEX_MAP_BUSYBOX_OK',body)
 checks['limited_changes_persisted']=all(line(x,body) for x in (b'FLEX_MAP_LIMIT_OK',b'FLEX_MAP_OK fault-reload',f'M_fault_{commit}'.encode(),b'FLEX_MAP_FAULT_RELOAD_OK')) and re.search(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=4 exited=0 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?:\r?\n|$)',body) is not None
 checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)+5
 return {'schema':'flex-linux-shared-file-mappings/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
