# SPDX-License-Identifier: AGPL-3.0-only
"""Build unmodified musl release fixtures; never commit generated binaries."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
VERSION='1.2.6'
SOURCE_SHA256='d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a'
ROOT=Path(__file__).resolve().parents[1]

def build(directory):
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    archive=directory/f'musl-{VERSION}.tar.gz'
    if not archive.exists():
        errors=[]
        for base in ('https://musl.libc.org/releases/','https://distfiles.alpinelinux.org/distfiles/edge/','https://sources.buildroot.net/musl/'):
            try:
                data=urllib.request.urlopen(base+archive.name,timeout=60).read()
                if hashlib.sha256(data).hexdigest()!=SOURCE_SHA256:raise ValueError('musl source SHA256 mismatch')
                archive.write_bytes(data);break
            except Exception as error:errors.append(str(error))
        else:raise RuntimeError('; '.join(errors))
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=SOURCE_SHA256:raise ValueError('musl source SHA256 mismatch')
    source=directory/f'musl-{VERSION}';install=directory/'install'
    if not source.exists():
        with tarfile.open(archive) as tar:tar.extractall(directory,filter='data')
    if not (install/'bin/musl-gcc').exists():
        with (directory/'musl-build.log').open('w') as log:
            subprocess.run(['./configure','--prefix='+str(install),'--syslibdir='+str(install/'lib')],cwd=source,stdout=log,stderr=subprocess.STDOUT,check=True)
            subprocess.run(['make','-j4'],cwd=source,stdout=log,stderr=subprocess.STDOUT,check=True)
            subprocess.run(['make','install'],cwd=source,stdout=log,stderr=subprocess.STDOUT,check=True)
    cc=str(install/'bin/musl-gcc');fixtures=ROOT/'tests/fixtures'
    flags=['-O1','-Wl,--build-id=none']
    subprocess.run([cc,*flags,'-shared','-fPIC',str(fixtures/'compact_dynamic_library.c'),'-o',str(directory/'libflex.so')],check=True,capture_output=True)
    for name in ('hello','dlopen','needed'):
        command=[cc,*flags,'-fPIE','-pie','-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1',str(fixtures/f'compact_dynamic_{name}.c'),'-o',str(directory/('dynamic-'+name))]
        if name=='needed':command+=['-L'+str(directory),'-Wl,-rpath,/lib','-lflex']
        subprocess.run(command,check=True,capture_output=True)
    from phase9_process import FLAGS
    subprocess.run(['cc',*FLAGS,str(fixtures/'compact_process_start.S'),str(fixtures/'compact_dynamic_memory.c'),'-o',str(directory/'dynamic-memory')],check=True,capture_output=True)
    shutil.copy2(install/'lib/libc.so',directory/'musl-libc.so')
    return {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('musl-libc.so','libflex.so','dynamic-hello','dynamic-dlopen','dynamic-needed','dynamic-memory')}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--build',required=True);args=parser.parse_args();print(build(args.build))
