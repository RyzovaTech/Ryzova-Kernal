# SPDX-License-Identifier: GPL-3.0-only
"""Historical unmodified TinyCC fixture: freestanding C -> ELF, no host exec."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from pinned_source import fetch_pinned
from phase9_dynamic import build as build_musl, VERSION as MUSL_VERSION, SOURCE_SHA256 as MUSL_SHA256
SHA256='de23af78fca90ce32dff2dd45b3432b2334740bb9bb7b05bf60fdbfc396ceb9c'

def source(commit):
    if not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('expected source commit')
    message='FLEX_COMPILED_IN_GUEST\nC_'+commit+'\n'
    literal=message.replace('\n','\\n')
    return (f'static const char message[]="{literal}";\n'
        'void _start(void){__asm__ volatile("syscall"::"a"(1),"D"(1),"S"(message),"d"(sizeof(message)-1):"rcx","r11","memory");'
        '__asm__ volatile("syscall"::"a"(60),"D"(0):"rcx","r11","memory");}\n').encode()

def prefetch(directory):
    """Fetch exact musl and TinyCC source tarballs for CI cache priming."""
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    musl = directory / ('musl-' + MUSL_VERSION + '.tar.gz')
    fetch_pinned(musl, (
        'https://musl.libc.org/releases/' + musl.name,
        'https://distfiles.alpinelinux.org/distfiles/edge/' + musl.name,
        'https://sources.buildroot.net/musl/' + musl.name,
    ), MUSL_SHA256, max_bytes=10*1024*1024)
    tcc = directory / 'tcc-0.9.27.tar.bz2'
    fetch_pinned(tcc, (
        'https://download.savannah.gnu.org/releases/tinycc/' + tcc.name,
        'https://download-mirror.savannah.gnu.org/releases/tinycc/' + tcc.name,
        'https://mirror.ossplanet.net/mirror/nongnu/tinycc/' + tcc.name,
    ), SHA256, max_bytes=4*1024*1024)
    return musl, tcc


def build(directory):
    directory=Path(directory).resolve()
    _, archive = prefetch(directory)
    build_musl(directory)
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
    parser=argparse.ArgumentParser()
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--build')
    choice.add_argument('--prefetch')
    args=parser.parse_args()
    if args.prefetch:
        for archive in prefetch(args.prefetch):
            print('SHA256 pinned source:', archive)
    else:
        print(build(args.build))
