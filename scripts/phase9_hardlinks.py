# SPDX-License-Identifier: AGPL-3.0-only
"""Native shared-inode lifetimes, immutable grants and saved-name qualification."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
import subprocess
from phase9_process import FLAGS
from phase9_symlinks import commands as symlink_commands,start as symlink_start
ROOT=Path(__file__).resolve().parents[1]
CASES=('basic','offsets','unlink-open','rename','symlinks','at','errors','shared','times','churn','quota','grants')
SCRIPT=b'''set -e
/busybox mkdir /tmp/hard
echo hard-content > /tmp/hard/file
/busybox ln /tmp/hard/file /tmp/hard/alias
/busybox cp -l /tmp/hard/file /tmp/hard/third
test /tmp/hard/file -ef /tmp/hard/alias
/busybox stat -c %h /tmp/hard/file
echo shared-update >> /tmp/hard/alias
/busybox rm /tmp/hard/file
/busybox stat -c %h /tmp/hard/alias
/busybox cmp /tmp/hard/alias /tmp/hard/third
/busybox cat /tmp/hard/third
/busybox rm -r /tmp/hard
echo FLEX_HARDLINK_SHELL_OK
'''
def fixtures(directory,commit):
 directory=Path(directory);path=directory/'hardlinks.elf'
 subprocess.run(['cc',*FLAGS,str(ROOT/'tests/fixtures/compact_process_start.S'),str(ROOT/'tests/fixtures/compact_hardlinks.c'),'-o',str(path)],check=True,capture_output=True)
 (directory/'hardlinks-script').write_bytes(SCRIPT)
 return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('hardlinks.elf','hardlinks-script')}
@lru_cache(maxsize=16)
def start(commit):return symlink_start(commit)+len(symlink_commands(commit))
def commands(commit):
 if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
 ops=['hget http://10.0.2.2:8000/hardlinks.elf > /tmp/hl-elf','sha1sum -2 256 /tmp/hl-elf','hget http://10.0.2.2:8000/hardlinks-script > /tmp/hl-script','sha1sum -2 256 /tmp/hl-script','cat /compact/linux/filesystem','cat /compact/linux/persistence','echo FLEX_HARDLINK_BEGIN']
 for mode in CASES:ops.append(f'$c -j -x /tmp/hl-elf /tmp/hl-elf /tmp/links {mode} H_{mode}_{commit} && echo FLEX_HARDLINK_{mode}_RUN_OK')
 for mode,flags,marker,token in (('create','-W /tmp/hl-state','SAVE','saved'),('reload','-R /tmp/hl-state -W /tmp/hl-next','RELOAD','saved'),('reload-mutated','-R /tmp/hl-next','MUTATED','saved'),('single','-W /tmp/hl-single','SINGLE','single'),('reload-single','-R /tmp/hl-single','SINGLE_RELOAD','single'),('symlinks','-W /tmp/hl-sym','SYM_SAVE','sym'),('reload-symlinks','-R /tmp/hl-sym','SYM_RELOAD','sym')):
  ops.append(f'$c -j {flags} /tmp/hl-elf /tmp/links {mode} H_{token}_{commit} && echo FLEX_HARDLINK_{marker}_OK')
 ops += ['$c -j -b 4194304 -x /busybox -i /tmp/hl-script /tmp/busybox ash /input && echo FLEX_HARDLINK_SHELL_RUN_OK','echo FLEX_HARDLINK_END']
 first=start(commit)
 return [op+f'; echo RYZOVA_RUNTIME_STAGE_{first+i}' for i,op in enumerate(ops)]+['echo FLEX_HARDLINK_DONE']
def inspect(serial,commit,digests):
 def line(value,body=serial):return re.search(rb'(?:^|\r?\n)'+re.escape(value)+rb'(?:\r?\n|$)',body) is not None
 match=re.search(rb'(?:^|\r?\n)FLEX_HARDLINK_BEGIN\r?\n(.*?)\r?\nFLEX_HARDLINK_END(?:\r?\n|$)',serial,re.S);body=match.group(1) if match else b''
 checks={'section':match is not None,'done':line(b'FLEX_HARDLINK_DONE'),'hardlink_discovery':b'hardlinks=guest-inode-aliases' in serial,'snapshot_discovery':b'shared-inodes-format=FLEXFS3 import-extra=FLEXFS3' in serial,'no_panic':re.search(rb'(?im)^panic:',serial) is None,'stages':all(line(f'RYZOVA_RUNTIME_STAGE_{i}'.encode()) for i in range(start(commit),start(commit)+len(commands(commit))-1))}
 for name,target in (('hardlinks.elf','hl-elf'),('hardlinks-script','hl-script')):
  digest=digests.get(name,'');checks[name]=bool(re.fullmatch('[a-f0-9]{64}',digest) and re.search(rb'(?:^|\r?\n)'+digest.encode()+rb'\s+/tmp/'+target.encode()+rb'(?:\r?\n|$)',serial))
 checks['script_digest']=digests.get('hardlinks-script')==hashlib.sha256(SCRIPT).hexdigest()
 for mode in CASES:checks[mode]=all(line(x,body) for x in (f'FLEX_HARDLINK_OK {mode}'.encode(),f'H_{mode}_{commit}'.encode(),f'FLEX_HARDLINK_{mode}_RUN_OK'.encode()))
 for mode,marker in (('create','SAVE'),('reload','RELOAD'),('reload-mutated','MUTATED'),('single','SINGLE'),('reload-single','SINGLE_RELOAD'),('symlinks','SYM_SAVE'),('reload-symlinks','SYM_RELOAD')):checks[marker]=line(f'FLEX_HARDLINK_OK {mode}'.encode(),body) and line(f'FLEX_HARDLINK_{marker}_OK'.encode(),body)
 for token,count in (('saved',3),('single',2),('sym',2)):checks['challenge_'+token]=len(re.findall(rb'(?:^|\r?\n)H_'+token.encode()+b'_'+commit.encode()+rb'(?=\r?\n|$)',body))==count
 checks['unmodified_busybox']=all(line(x,body) for x in (b'FLEX_HARDLINK_SHELL_OK',b'FLEX_HARDLINK_SHELL_RUN_OK',b'3',b'2',b'hard-content',b'shared-update'))
 checks['clean_results']=len(re.findall(rb'(?:^|\r?\n)COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9][0-9]* syscalls=[1-9][0-9]*(?=\r?\n|$)',body))==len(CASES)+8
 return {'schema':'flex-linux-hardlinks/v1','source_commit':commit,'fixture_sha256':digests,'checks':checks,'passed':all(checks.values())}
