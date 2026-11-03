# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-03B/C and aggregate arena enforcement; full RESOURCE remains pending."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_private_maps import commands as previous_commands,start as previous_start
ROOT=Path(__file__).resolve().parents[1]
CASES=('basic','fork','fixed','release','anon-futex','file-futex','private-futex','bitset','requeue','timeout','unmap-wait','sessions','groups','nofile','hard-limit','address-limit','prlimit','exec','quota','nproc','arena-budget','key-pin-quota')
def fixtures(directory,commit):
 path=Path(directory)/'runtime.elf'
 subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_runtime.c'),'-o',str(path)],check=True,capture_output=True)
 return {'runtime.elf':hashlib.sha256(path.read_bytes()).hexdigest()}
@lru_cache(maxsize=16)
def start(commit):return previous_start(commit)+len(previous_commands(commit))
def commands(commit):
 if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
 ops=['hget http://10.0.2.2:8000/runtime.elf > /tmp/rt-elf','sha1sum -2 256 /tmp/rt-elf','p=/tmp/rt-elf; o=/tmp/runtime','echo FLEX_PROC_RESOURCE_BEGIN']
 for mode in CASES:
  budget=' -B 16777216' if mode=='arena-budget' else ''
  ops.append(f'$c -j{budget} -x $p $p $o {mode} C_{mode}_{commit} && echo FLEX_PROC_RESOURCE_{mode}_RUN_OK')
 ops+=['echo FLEX_PROC_RESOURCE_END']
 return [op+f'; echo RYZOVA_RUNTIME_STAGE_{start(commit)+i}' for i,op in enumerate(ops)]+['echo FLEX_PROC_RESOURCE_DONE']
def inspect(serial,commit,digests):
 def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
 match=re.search(rb'(?:^|\r?\n)FLEX_PROC_RESOURCE_BEGIN\r?\n(.*?)\r?\nFLEX_PROC_RESOURCE_END(?:\r?\n|$)',serial,re.S);body=match.group(1) if match else b''
 checks={'section':match is not None,'done':line(b'FLEX_PROC_RESOURCE_DONE'),'no_panic':re.search(rb'(?im)^panic:',serial) is None,'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1))}
 digest=digests.get('runtime.elf','');checks['fixture_digest']=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/rt-elf(?:\r?\n|$)',serial))
 for mode in CASES:checks[mode]=all(line(x,body) for x in (f'FLEX_PROC_RESOURCE_OK {mode}'.encode(),f'C_{mode}_{commit}'.encode(),f'FLEX_PROC_RESOURCE_{mode}_RUN_OK'.encode()))
 checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)
 measurements=[{'arena_peak_bytes':int(a),'shared_peak_pages':int(b)} for a,b in re.findall(rb'(?:^|\r?\n)COMPACT_RESOURCE_STATS arena_peak=([0-9]+) shared_peak=([0-9]+)(?=\r?\n|$)',body)]
 checks['measured_arena_peaks']=len(measurements)==len(CASES) and all(16777216<=m['arena_peak_bytes']<=150994944 and m['shared_peak_pages']<=64 for m in measurements)
 checks['one_arena_denial']=line(b'COMPACT_RESOURCE_STATS arena_peak=16777216 shared_peak=1',body)
 return {'schema':'compact-linux-phase3-runtime/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values()),'measurements':measurements,'measurement_order':list(CASES),'phase_complete':False,'increments':['CLX-03B','CLX-03C','CLX-03D-arena-enforcement'],'remaining':['all-named-target-image-memory-steps-time-fd-filesystem-network-measurements'],'v1_complete':False}
