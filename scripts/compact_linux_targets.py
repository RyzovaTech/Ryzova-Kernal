# SPDX-License-Identifier: AGPL-3.0-only
"""Checksum-locked musl target builds. Building a binary never qualifies its guest ABI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/'ryzova/compact/linux-target-sources.json'
TRIPLE='x86_64-linux-musl'

def validate(lock):
    errors=[];sources=lock.get('sources',[]);ids=[s.get('id') for s in sources]
    if lock.get('schema')!='compact-linux-target-sources/v1' or len(ids)!=len(set(ids)):errors.append('invalid lock/schema')
    targets=json.loads((ROOT/'ryzova/compact/linux-v1-plan.json').read_text())['targets']
    for target in targets:
        source=next((s for s in sources if s.get('id')==target['id']),{})
        if target['version'] not in source.get('archive',''):errors.append('missing frozen target '+target['id'])
    for s in sources:
        if s.get('algorithm') not in ('sha256','sha512') or len(s.get('digest',''))!={'sha256':64,'sha512':128}.get(s.get('algorithm')) or any(c not in '0123456789abcdef' for c in s.get('digest','')):errors.append('invalid checksum '+str(s.get('id')))
        if not s.get('urls') or any(not u.startswith('https://') or not u.endswith('/'+s['archive']) for u in s['urls']):errors.append('invalid source URL')
    return errors

class Build:
    def __init__(self,out,driver,jobs):
        self.out=Path(out).resolve();self.out.mkdir(parents=True,exist_ok=True)
        self.driver=Path(driver).resolve();self.jobs=jobs;self.lock=json.loads(LOCK.read_text())
        errors=validate(self.lock)
        if errors:raise ValueError('; '.join(errors))
        self.archives=self.out/'sources';self.src=self.out/'src';self.logs=self.out/'logs';self.root=self.out/'root';self.cross=self.out/'cross'
        for p in (self.archives,self.src,self.logs,self.root):p.mkdir(parents=True,exist_ok=True)
        self.env=dict(os.environ,SOURCE_DATE_EPOCH='1744243200',LC_ALL='C',TZ='UTC')
        self.commands=[]
        self.reused_stages=[]
    def run(self,name,argv,cwd,env=None):
        self.commands.append({'stage':name,'argv':list(map(str,argv)),'cwd':str(cwd)})
        print('BUILD',name,flush=True)
        command_env=dict(env or self.env,PWD=str(Path(cwd).resolve()))
        with (self.logs/(name+'.log')).open('a') as log:
            subprocess.run(list(map(str,argv)),cwd=cwd,env=command_env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=5400)
    def sources(self):
        result={}
        for s in self.lock['sources']:
            path=self.archives/s['archive']
            if not path.exists():
                failures=[]
                for url in s['urls']:
                    temp=path.with_suffix(path.suffix+'.part')
                    try:
                        with urllib.request.urlopen(url,timeout=60) as response,temp.open('wb') as out:shutil.copyfileobj(response,out)
                        if hashlib.new(s['algorithm'],temp.read_bytes()).hexdigest()!=s['digest']:raise ValueError('checksum mismatch')
                        temp.replace(path);break
                    except Exception as e:failures.append(str(e));temp.unlink(missing_ok=True)
                else:raise RuntimeError(s['id']+': '+'; '.join(failures))
            if hashlib.new(s['algorithm'],path.read_bytes()).hexdigest()!=s['digest']:raise ValueError('cached source checksum mismatch '+s['id'])
            dest=self.src/s['id'];dest.mkdir(exist_ok=True)
            if not any(dest.iterdir()):
                archive=path
                if path.suffix=='.lz':
                    archive=dest/'unpack.tar'
                    with archive.open('wb') as out:subprocess.run(['lzip','-dc',str(path)],stdout=out,check=True,timeout=120)
                with tarfile.open(archive) as tar:tar.extractall(dest,filter='data')
                if path.suffix=='.lz':archive.unlink()
            children=list(dest.iterdir())
            if len(children)!=1 or not children[0].is_dir():raise ValueError('expected one source root '+s['id'])
            result[s['id']]=children[0]
        return result
    def toolchain(self,src,native=False):
        name='native' if native else 'cross';build=self.out/('build-'+name);build.mkdir(exist_ok=True)
        driver_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.driver,text=True).strip()
        if driver_commit!=self.lock['build_driver']['commit']:raise ValueError('build driver revision mismatch')
        shutil.copy2(self.driver/'litecross/Makefile',build/'Makefile')
        config=['TARGET = '+TRIPLE,'GCC_CONFIG = --enable-languages='+('c' if native else 'c,c++')+' --disable-libquadmath --disable-libgomp --disable-libstdcxx-pch --with-arch=x86-64 --with-tune=generic', 'COMMON_CONFIG = CFLAGS="-O2 -march=x86-64 -mtune=generic" CXXFLAGS="-O2 -march=x86-64 -mtune=generic"', 'GCC_CONFIG_FOR_TARGET = CFLAGS_FOR_TARGET="-O2 -march=x86-64 -mtune=generic" CXXFLAGS_FOR_TARGET="-O2 -march=x86-64 -mtune=generic"']
        for key,ident in [('GCC','gcc'),('BINUTILS','binutils'),('MUSL','musl'),('GMP','gmp'),('MPC','mpc'),('MPFR','mpfr'),('LINUX','linux')]:config.append(key+'_SRCDIR = '+str(src[ident]))
        env=self.env.copy()
        if native:
            config+=['HOST = '+TRIPLE,'BINUTILS_CONFIG = --disable-gprofng'];env.update(PATH=str(self.cross/'bin')+os.pathsep+env['PATH'],CC=TRIPLE+'-gcc',CXX=TRIPLE+'-g++',AR=TRIPLE+'-ar',RANLIB=TRIPLE+'-ranlib',LDFLAGS='-static-libstdc++ -static-libgcc')
        output=self.out/'native-toolchain' if native else self.cross
        signature=hashlib.sha256(('\n'.join(config)+driver_commit+json.dumps({x['id']:x['digest'] for x in self.lock['sources'] if x['id'] in ('gcc','binutils','musl','gmp','mpc','mpfr','linux')},sort_keys=True)).encode()).hexdigest()
        checkpoint=output/'toolchain-stage.json'
        if checkpoint.exists():
            saved=json.loads(checkpoint.read_text())
            if saved.get('signature')==signature and all((output/p['path']).is_file() and hashlib.sha256((output/p['path']).read_bytes()).hexdigest()==p['sha256'] for p in saved.get('files',[])) and saved.get('files'):
                print('REUSE',name,'verified checkpoint',flush=True);self.reused_stages.append(name);shutil.rmtree(build)
                if native:shutil.copytree(output,self.root,dirs_exist_ok=True,symlinks=True)
                return
        if output.exists():shutil.rmtree(output)
        (build/'config.mak').write_text('\n'.join(config)+'\n')
        self.run(name,['make','-j'+str(self.jobs)],build,env)
        self.run(name+'-install',['make','install','OUTPUT='+str(output)],build,env)
        records=[]
        for file in sorted(output.rglob('*')):
            if file.is_file() and not file.is_symlink():records.append({'path':str(file.relative_to(output)),'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
        checkpoint.write_text(json.dumps({'signature':signature,'files':records},indent=2)+'\n')
        if native:shutil.copytree(output,self.root,dirs_exist_ok=True,symlinks=True)
        shutil.rmtree(build)
    def app(self,name,source,args,env,install='install'):
        build=self.out/('build-'+name);build.mkdir(exist_ok=True)
        self.run(name+'-configure',[source/'configure',*args],build,env)
        self.run(name+'-make',['make','-j'+str(self.jobs)],build,env)
        self.run(name+'-install',['make',install,'DESTDIR='+str(self.root)],build,env)
        shutil.rmtree(build)
    def build(self,stage='all'):
        src=self.sources()
        if stage=='sources':return
        self.toolchain(src)
        if stage=='cross':return
        self.toolchain(src,True)
        if stage=='native':return
        (self.root/'usr').mkdir(exist_ok=True)
        shutil.copytree(self.root/'include',self.root/'usr/include',dirs_exist_ok=True,symlinks=True)
        env=dict(self.env,PATH=str(self.cross/'bin')+os.pathsep+self.env['PATH'],CC=TRIPLE+'-gcc',CXX=TRIPLE+'-g++',AR=TRIPLE+'-ar',RANLIB=TRIPLE+'-ranlib',CFLAGS='-O2 -march=x86-64 -mtune=generic',CPPFLAGS='-I'+str(self.root/'usr/include'),LDFLAGS='-L'+str(self.root/'usr/lib'),PKG_CONFIG='/bin/false')
        # Packages are built against the pinned musl cross sysroot and explicit dependencies.
        self.run('zlib-configure',['./configure','--prefix=/usr'],src['zlib'],env)
        self.run('zlib-make',['make','-j'+str(self.jobs)],src['zlib'],env)
        self.run('zlib-install',['make','install','DESTDIR='+str(self.root)],src['zlib'],env)
        self.run('openssl-configure',['./Configure','linux-x86_64','--prefix=/usr','--openssldir=/etc/ssl','--libdir=lib','shared','no-tests','no-zlib','no-asm'],src['openssl'],env)
        self.run('openssl-make',['make','-j'+str(self.jobs)],src['openssl'],env)
        self.run('openssl-install',['make','install_sw','DESTDIR='+str(self.root)],src['openssl'],env)
        common=['--build='+subprocess.check_output([str(src['gcc']/'config.guess')],text=True).strip(),'--host='+TRIPLE,'--prefix=/usr']
        self.app('curl',src['curl'],[*common,'--with-openssl='+str(self.root/'usr'),'--with-zlib='+str(self.root/'usr'),'--disable-ldap','--disable-ldaps','--disable-manual','--without-libpsl','--without-brotli','--without-zstd','--without-libidn2','--without-nghttp2','--without-librtmp','--without-libssh2','--enable-shared','--disable-static'],env)
        genv=dict(env,NO_GETTEXT='YesPlease',NO_TCLTK='YesPlease',NO_PERL='YesPlease',NO_PYTHON='YesPlease',CURL_CONFIG=str(self.root/'usr/bin/curl-config'))
        self.run('git-configure',['make','configure'],src['git'],genv)
        self.run('git-config',['./configure',*common,'--with-openssl='+str(self.root/'usr'),'--with-curl='+str(self.root/'usr'),'--with-zlib='+str(self.root/'usr'),'--without-tcltk'],src['git'],genv)
        self.run('git-make',['make','-j'+str(self.jobs),'NO_GETTEXT=YesPlease','NO_TCLTK=YesPlease','NO_PERL=YesPlease','NO_PYTHON=YesPlease'],src['git'],genv)
        self.run('git-install',['make','install','DESTDIR='+str(self.root),'NO_GETTEXT=YesPlease','NO_TCLTK=YesPlease','NO_PERL=YesPlease','NO_PYTHON=YesPlease'],src['git'],genv)
        self.app('make',src['make'],[*common,'--without-guile','--disable-nls'],env)
        self.run('busybox-config',['make','allnoconfig'],src['busybox'],env)
        config=src['busybox']/'.config';text=config.read_text()
        for key in ('STATIC','DESKTOP','LONG_OPTS','ASH','SH_IS_ASH','ASH_JOB_CONTROL','ASH_ALIAS','ASH_MATH_SUPPORT','ASH_BUILTIN_ECHO','ASH_BUILTIN_PRINTF','ASH_BUILTIN_TEST','ASH_CMDCMD','ECHO','PRINTF','TEST','CAT','CP','MV','RM','MKDIR','RMDIR','LS','PWD','TOUCH','HEAD','TAIL','SORT','WC','GREP','EGREP','FGREP','SED','FIND','FEATURE_FIND_NAME','FEATURE_FIND_TYPE','FEATURE_FIND_PRINT0','FEATURE_FIND_EXEC','TAR','FEATURE_TAR_CREATE','FEATURE_TAR_GZIP','GZIP','GUNZIP','WGET','FEATURE_WGET_STATUSBAR','SHA256SUM','CHMOD','LN','TRUE','FALSE','SLEEP','ENV','UNAME'):
            text=text.replace('# CONFIG_'+key+' is not set','CONFIG_'+key+'=y')
        config.write_text(text);self.run('busybox-oldconfig',['make','oldconfig'],src['busybox'],env)
        self.run('busybox-make',['make','-j'+str(self.jobs),'CC='+env['CC'],'HOSTCC=cc'],src['busybox'],env)
        shutil.copy2(src['busybox']/'busybox',self.root/'bin/busybox')
        for key in ('sh','cat','echo','mkdir','rm','cp','mv','touch','ln','true','false','sleep','env','grep','sed','find','tar'):
            path=self.root/'bin'/key
            if not path.exists():path.symlink_to('busybox')
        # A version-identical build Python is required by CPython's cross build.
        host=self.out/'host-python';host.mkdir(exist_ok=True)
        self.run('host-python-config',[src['python']/'configure','--prefix='+str(host/'install'),'--without-ensurepip','--disable-test-modules'],host,self.env)
        self.run('host-python-make',['make','-j'+str(self.jobs)],host,self.env)
        penv=dict(env,ac_cv_file__dev_ptmx='no',ac_cv_file__dev_ptc='no',ac_cv_buggy_getaddrinfo='no')
        self.app('python',src['python'],[*common,'--with-build-python='+str(host/'python'),'--without-ensurepip','--disable-test-modules','--with-openssl='+str(self.root/'usr'),'--with-openssl-rpath=no'],penv)
        (self.root/'tmp').mkdir(exist_ok=True);(self.root/'tmp').chmod(0o1777)
        (self.root/'dev').mkdir(exist_ok=True)
        self.run('dev-null',['sudo','mknod','-m','666',str(self.root/'dev/null'),'c','1','3'],self.out)
        self.run('dev-zero',['sudo','mknod','-m','666',str(self.root/'dev/zero'),'c','1','5'],self.out)
        for binary in ('gcc','cc','as','ld','ar','nm','readelf','ranlib','strip'):
            path=self.root/'bin'/binary
            target=self.root/'bin'/(TRIPLE+'-'+('gcc' if binary=='cc' else binary))
            if not path.exists() and target.exists():path.symlink_to(target.name)
            elif not target.exists() and path.exists():target.symlink_to(path.name)
            elif not path.exists():raise ValueError('missing native tool '+binary)
        self.manifest()
    def manifest(self):
        files=[]
        for path in sorted(self.root.rglob('*')):
            if path.is_file() and not path.is_symlink():
                data=path.read_bytes();files.append({'path':'/'+str(path.relative_to(self.root)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'elf':data[:4]==b'\x7fELF'})
        report={'host_compiler':subprocess.check_output(['cc','--version'],text=True).splitlines()[0],'host_system':os.uname().release,'schema':'compact-linux-target-build/v1','source_lock_sha256':hashlib.sha256(LOCK.read_bytes()).hexdigest(),'driver_commit':self.lock['build_driver']['commit'],'abi':TRIPLE,'build_commands':self.commands,'verified_reused_stages':self.reused_stages,'files':files,'guest_qualified':False,'phase3_complete':False}
        (self.out/'target-build.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);p.add_argument('--driver',type=Path);p.add_argument('--jobs',type=int,default=2);p.add_argument('--check-lock',action='store_true');p.add_argument('--stage',choices=('all','sources','cross','native','apps'),default='all');args=p.parse_args()
    if args.check_lock:
        errors=validate(json.loads(LOCK.read_text()));print(json.dumps({'lock_valid':not errors,'errors':errors,'guest_qualified':False}));raise SystemExit(bool(errors))
    if not args.output or not args.driver or not 1<=args.jobs<=4:p.error('output, pinned driver and 1..4 jobs required')
    Build(args.output,args.driver,args.jobs).build(args.stage)
