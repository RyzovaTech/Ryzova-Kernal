# SPDX-License-Identifier: AGPL-3.0-only
"""Source-built native Linux symbolic-link and saved-namespace qualification."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_external import commands as external_commands,start as external_start
ROOT=Path(__file__).resolve().parents[1]
CASES=('basic','nofollow','loops','at','rename','times','grants','trailing','boundary','permissions','trailing-mutations')
SCRIPT=b'''set -e
/busybox mkdir -p /tmp/tree/sub
echo linked-content > /tmp/tree/sub/file
/busybox ln -s sub/file /tmp/tree/link
/busybox ln -s tree /tmp/alias
test -L /tmp/tree/link
/busybox cat /tmp/alias/link
/busybox readlink /tmp/tree/link
/busybox cp -P /tmp/tree/link /tmp/tree/copy
test -L /tmp/tree/copy
/busybox cat /tmp/tree/copy
/busybox rm -r /tmp/alias
test -d /tmp/tree
/busybox cat /tmp/tree/sub/file
echo FLEX_SYMLINK_SHELL_OK
'''
def fixtures(directory,commit):
 directory=Path(directory);path=directory/'symlinks.elf'
 subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_symlinks.c'),'-o',str(path)],check=True,capture_output=True)
 (directory/'symlinks-script').write_bytes(SCRIPT)
 return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('symlinks.elf','symlinks-script')}
@lru_cache(maxsize=16)
def start(commit):return external_start(commit)+len(external_commands(commit))
def commands(commit):
 if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
 ops=['hget http://10.0.2.2:8000/symlinks.elf > /tmp/sl-elf','sha1sum -2 256 /tmp/sl-elf','hget http://10.0.2.2:8000/symlinks-script > /tmp/sl-script','sha1sum -2 256 /tmp/sl-script','cat /compact/linux/filesystem','cat /compact/linux/persistence','echo FLEX_SYMLINK_BEGIN']
 for mode in CASES:ops.append(f'$c -j -x /tmp/sl-elf /tmp/sl-elf /tmp/links {mode} S_{mode}_{commit} && echo FLEX_SYMLINK_{mode}_RUN_OK')
 ops += [f'$c -j -W /tmp/sl-state /tmp/sl-elf /tmp/links create S_saved_{commit} && echo FLEX_SYMLINK_SAVE_OK',f'$c -j -R /tmp/sl-state /tmp/sl-elf /tmp/links reload S_saved_{commit} && echo FLEX_SYMLINK_RELOAD_OK',f"$c -j -R /tmp/sl-state -x '/tmp/links/link=/tmp/sl-elf' /tmp/sl-elf /tmp/links shadow S_shadow_{commit} && echo FLEX_SYMLINK_SHADOW_OK","$c -j -b 4194304 -x /busybox -i /tmp/sl-script /tmp/busybox ash /input && echo FLEX_SYMLINK_SHELL_RUN_OK",'echo FLEX_SYMLINK_END']
 first=start(commit)
 return [op+f'; echo RYZOVA_RUNTIME_STAGE_{first+i}' for i,op in enumerate(ops)]+['echo FLEX_SYMLINK_DONE']
def inspect(serial,commit,digests):
 def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
 match=re.search(rb'(?:^|\r?\n)FLEX_SYMLINK_BEGIN\r?\n(.*?)\r?\nFLEX_SYMLINK_END(?:\r?\n|$)',serial,re.S);body=match.group(1) if match else b''
 checks={'section':match is not None,'done':line(b'FLEX_SYMLINK_DONE'),'link_discovery':b'symlinks=guest-paths,40-hop-limit' in serial,'snapshot_discovery':b'format=FLEXFS2 import=FLEXFS1,FLEXFS2' in serial,'no_panic':re.search(rb'(?im)^panic:',serial) is None,'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1))}
 for name,target in (('symlinks.elf','sl-elf'),('symlinks-script','sl-script')):
  digest=digests.get(name,'');checks[name]=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/'+target.encode()+rb'(?:\r?\n|$)',serial))
 checks['script_digest']=digests.get('symlinks-script')==hashlib.sha256(SCRIPT).hexdigest()
 for mode in CASES:checks[mode]=all(line(x,body) for x in (f'FLEX_SYMLINK_OK {mode}'.encode(),f'S_{mode}_{commit}'.encode(),f'FLEX_SYMLINK_{mode}_RUN_OK'.encode()))
 checks['saved_links']=all(line(x,body) for x in (b'FLEX_SYMLINK_OK create',b'FLEX_SYMLINK_OK reload',b'FLEX_SYMLINK_SAVE_OK',b'FLEX_SYMLINK_RELOAD_OK')) and len(re.findall(rb'(?:^|\r?\n)S_saved_'+commit.encode()+rb'(?=\r?\n|$)',body))==2
 checks['immutable_grant_shadow']=all(line(x,body) for x in (b'FLEX_SYMLINK_OK shadow',f'S_shadow_{commit}'.encode(),b'FLEX_SYMLINK_SHADOW_OK'))
 checks['unmodified_busybox']=line(b'FLEX_SYMLINK_SHELL_OK',body) and line(b'FLEX_SYMLINK_SHELL_RUN_OK',body) and line(b'sub/file',body) and len(re.findall(rb'(?:^|\r?\n)linked-content(?=\r?\n|$)',body))==3
 checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)+4
 return {'schema':'flex-linux-symlinks/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
