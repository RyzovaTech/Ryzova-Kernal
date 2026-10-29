# SPDX-License-Identifier: AGPL-3.0-only
"""Historical unmodified TinyCC fixture: freestanding C -> ELF, no host exec."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request
from phase9_dynamic import build as build_musl
SHA256='de23af78fca90ce32dff2dd45b3432b2334740bb9bb7b05bf60fdbfc396ceb9c'

def source(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    message='FLEX_COMPILED_IN_GUEST\nC_'+commit+'\n'
    literal=message.replace('\n','\\n')
    return (f'static const char message[]="{literal}";\n'
        'void _start(void){__asm__ volatile("syscall"::"a"(1),"D"(1),"S"(message),"d"(sizeof(message)-1):"rcx","r11","memory");'
        '__asm__ volatile("syscall"::"a"(60),"D"(0):"rcx","r11","memory");}\n').encode()

def build(directory):
    directory=Path(directory).resolve();build_musl(directory)
    archive=directory/'tcc-0.9.27.tar.bz2'
    if not archive.exists():archive.write_bytes(urllib.request.urlopen('https://download.savannah.gnu.org/releases/tinycc/'+archive.name,timeout=60).read())
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:raise ValueError('TinyCC source SHA256 mismatch')
    tree=directory/'tcc-0.9.27'
    if not tree.exists():
        with tarfile.open(archive) as tar:tar.extractall(directory,filter='data')
    if not (tree/'tcc').exists():
        with (directory/'tcc-build.log').open('w') as log:
            subprocess.run(['./configure','--cc='+str(directory/'install/bin/musl-gcc'),'--extra-cflags=-O1 -fcommon','--extra-ldflags=-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1'],cwd=tree,stdout=log,stderr=subprocess.STDOUT,check=True)
            subprocess.run(['make','-j4','tcc'],cwd=tree,stdout=log,stderr=subprocess.STDOUT,check=True)
    shutil.copy2(tree/'tcc',directory/'tcc-fixture')
    return hashlib.sha256((directory/'tcc-fixture').read_bytes()).hexdigest()

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--build',required=True);args=parser.parse_args();print(build(args.build))
