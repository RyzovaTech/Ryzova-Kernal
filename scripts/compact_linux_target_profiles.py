# SPDX-License-Identifier: AGPL-3.0-only
"""Measure real musl target smoke workloads on Linux and probe Flex admission separately."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
ROOT=Path(__file__).resolve().parents[1]
# Exact measured CPython 3.12.10 executable: 27,726,864 bytes.
# Keep these in lockstep with process.h; unit tests assert both ceilings.
IMAGE_MAX_BYTES=32*1024*1024
IMAGE_TOTAL_BYTES=48*1024*1024
TARGETS={
 'busybox':('/bin/busybox',['--help'],'1.35.0'),
 'python':('/usr/bin/python3.12',['-c','import json,pathlib,tempfile,threading,multiprocessing,subprocess,socket,ssl,hashlib,zlib; print(json.dumps({"version":__import__("sys").version,"ssl":ssl.OPENSSL_VERSION})); p=pathlib.Path("/tmp/python-proof"); p.write_text("proof"); assert p.read_text()=="proof"'],'3.12.10'),
 'git':('/usr/bin/git',['--version'],'2.49.0'),
 'gcc':('/bin/gcc',['--version'],'14.2.0'),
 'binutils':('/bin/as',['--version'],'2.43.1'),
 'make':('/usr/bin/make',['--version'],'4.4.1'),
 'musl':('/lib/libc.so',[],'1.2.6')}

def elf_info(data):
    if data[:6]!=b'\x7fELF\x02\x01' or len(data)<64 or int.from_bytes(data[18:20],'little')!=62:raise ValueError('not little-endian AMD64 ELF64')
    phoff=int.from_bytes(data[32:40],'little');size=int.from_bytes(data[54:56],'little');count=int.from_bytes(data[56:58],'little')
    if size!=56 or count>128 or phoff+size*count>len(data):raise ValueError('invalid program headers')
    loads=[];file_maps=[];dynamic=None;interpreter=None
    for i in range(count):
        h=data[phoff+i*size:phoff+(i+1)*size];kind=int.from_bytes(h[:4],'little');off=int.from_bytes(h[8:16],'little');at=int.from_bytes(h[16:24],'little');length=int.from_bytes(h[32:40],'little');memory=int.from_bytes(h[40:48],'little')
        if off+length>len(data):raise ValueError('truncated segment')
        if kind==1:loads.append((at,at+memory));file_maps.append((at,length,off))
        if kind==2:dynamic=(off,length)
        if kind==3:interpreter=data[off:off+length].rstrip(b'\0').decode('ascii')
    needed=[]
    if dynamic:
        strings=None;string_size=0;offsets=[]
        for pos in range(dynamic[0],dynamic[0]+dynamic[1]-15,16):
            tag=int.from_bytes(data[pos:pos+8],'little');value=int.from_bytes(data[pos+8:pos+16],'little')
            if tag==0:break
            if tag==1:offsets.append(value)
            if tag==5:strings=value
            if tag==10:string_size=value
        if offsets:
            table=next((off+strings-va for va,length,off in file_maps if strings is not None and va<=strings and strings-va+string_size<=length),None)
            if table is None:raise ValueError('invalid dynamic string table')
            for off in offsets:
                end=data.find(b'\0',table+off,table+string_size)
                if off>=string_size or end<0 or end-(table+off)>255:raise ValueError('invalid needed library name')
                name=data[table+off:end].decode('ascii')
                if '/' in name or not name:raise ValueError('unsupported needed library path')
                needed.append(name)
    return {'needed':needed,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'load_span_bytes':max((b for a,b in loads),default=0)-min((a for a,b in loads),default=0),'interpreter':interpreter}

def trace_metrics(paths):
    calls=collections.Counter();max_fd=2;read_bytes=write_bytes=network_bytes=unparsed=0
    for path in paths:
        for line in path.read_text(errors='replace').splitlines():
            match=re.search(r'\b([a-zA-Z_][a-zA-Z_0-9]*)\((.*)\)\s+=\s+(-?[0-9]+)',line)
            if not match:
                unparsed+=1;continue
            name,args,value=match.groups();value=int(value);calls[name]+=1
            if name in ('open','openat','creat','dup','dup2','dup3','socket','accept','accept4') and value>=0:max_fd=max(max_fd,value)
            if value>0:
                if name in ('read','readv','pread64'):read_bytes+=value
                if name in ('write','writev','pwrite64'):write_bytes+=value
                if name in ('sendto','sendmsg','recvfrom','recvmsg') or (name in ('read','write','readv','writev') and ('<TCP:' in args or '<UDP:' in args)):network_bytes+=value
    return {'observed_syscalls':dict(sorted(calls.items())),'unparsed_trace_lines':unparsed,'trace_metric':'completed parseable records; unfinished/resumed lines are not inferred','max_observed_fd':max_fd,'returned_read_bytes':read_bytes,'returned_write_bytes':write_bytes,'returned_network_bytes':network_bytes,'fd_metric':'largest descriptor returned by traced operations; not live-fd peak','scope':'Linux reference including chroot launcher; not Flex guest counters'}

def main(directory,output):
    directory=Path(directory).resolve();root=directory/'root';build=json.loads((directory/'target-build.json').read_text());logs=directory/'logs';records=[]
    core=ROOT/'ryzova/compat/linux';runner=directory/'jobs-probe'
    sources=[core/(n+'.c') for n in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',*map(str,sources),'-o',str(runner)],check=True,timeout=120)
    env=dict(os.environ,PATH='/usr/bin:/bin',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
    for target,(path,args,version) in TARGETS.items():
        binary=root/path.lstrip('/');info=elf_info(binary.read_bytes())
        resolved='/'+str(binary.resolve().relative_to(root))
        entry=next((x for x in build['files'] if x['path']==resolved),None)
        if not entry or entry['sha256']!=info['sha256'] or entry['bytes']!=info['bytes']:raise ValueError('artifact manifest mismatch '+target)
        trace=logs/(target+'-trace');usage=logs/(target+'-usage.json')
        command=['sudo','-n','/usr/bin/time','-q','-f','{"elapsed_seconds":%e,"max_child_rss_kib":%M,"user_seconds":%U,"system_seconds":%S}','-o',str(usage),'strace','-ff','-qq','-yy','-o',str(trace),'chroot',str(root),path,*args]
        start=time.monotonic();reference=subprocess.run(command,env=env,capture_output=True,timeout=120)
        elapsed=time.monotonic()-start;(logs/(target+'-reference.stdout')).write_bytes(reference.stdout);(logs/(target+'-reference.stderr')).write_bytes(reference.stderr)
        text=(reference.stdout+reference.stderr).decode(errors='replace');expected=1 if target=='musl' else 0
        reference_ok=reference.returncode==expected and version in text
        metrics=trace_metrics(logs.glob(target+'-trace.*'));metrics.update(json.loads(usage.read_text()));metrics['supervised_wall_seconds']=elapsed
        grants=[];libraries=[];pending=list(info['needed']);seen=set()
        if info['interpreter']:grants=['-x',info['interpreter']+'='+str(root/'lib/libc.so')]
        # Grant only the actual ELF dependency closure: unrelated large libraries
        # must not make a static BusyBox admission probe fail before it starts.
        while pending:
            name=pending.pop(0)
            if name in seen:continue
            seen.add(name);file=next((root/base/name for base in ('lib','usr/lib','usr/local/lib') if (root/base/name).is_file()),None)
            if file is None:raise ValueError('missing target dependency '+target+': '+name)
            dep=elf_info(file.read_bytes());virtual='/'+str(file.relative_to(root));libraries.append({'path':virtual,**dep});grants+=['-x',virtual+'='+str(file)];pending.extend(dep['needed'])
        guest_args=['--version'] if target=='python' else args
        guest=subprocess.run([str(runner),'-r','-b','1048576',*grants,str(binary),*guest_args],env=env,capture_output=True,timeout=30)
        (logs/(target+'-guest.stdout')).write_bytes(guest.stdout);(logs/(target+'-guest.stderr')).write_bytes(guest.stderr)
        result=re.search(rb'COMPACT_JOBS_RESULT status=([0-9]+) exited=([01]) exit=([0-9]+) steps=([0-9]+) syscalls=([0-9]+)',guest.stderr)
        actual={key:int(value) for key,value in zip(('status','exited','exit','steps','syscalls'),result.groups())} if result else None
        if actual:
            rip=re.search(rb' rip=([0-9a-f]+)',guest.stderr)
            actual['last_rip_hex']=rip.group(1).decode() if rip else None
            rejected=re.search(rb' unsupported_syscall=([0-9]+) unsupported_syscall_valid=([01])',guest.stderr)
            actual['unsupported_syscall_nr']=int(rejected.group(1)) if rejected and rejected.group(2)==b'1' else None
        success=bool(actual and actual['status']==0 and actual['exited'] and actual['exit']==expected and version.encode() in guest.stdout+guest.stderr)
        blockers=[]
        if info['bytes']>IMAGE_MAX_BYTES:blockers.append('ELF exceeds current bounded 32-MiB image ceiling')
        if info['load_span_bytes']+65536+4096>16*1024*1024:blockers.append('load span plus stack/guard exceeds current 16-MiB arena')
        for library in libraries:
            if library['bytes']>IMAGE_MAX_BYTES:blockers.append(library['path']+' exceeds current bounded 32-MiB grant image ceiling')
        if info['bytes']+sum(library['bytes'] for library in libraries)>IMAGE_TOTAL_BYTES:
            blockers.append('main image plus transitive library images exceed bounded 48-MiB aggregate ceiling')
        if len(grants)//2>16:blockers.append('dependency closure exceeds 16 executable/library grants')
        # First *actual code execution* probe for frozen CPython, separate
        # from the limited --version smoke. Never relabel as full stdlib V1.
        python_code_probe=None
        if target=='python':
            command=[str(runner),'-r','-b','1048576',*grants,str(binary),
                     '-c','print("CLX_PYTHON_CODE_OK")']
            attempt=subprocess.run(command,env=env,capture_output=True,timeout=30)
            (logs/'python-guest-code.stdout').write_bytes(attempt.stdout)
            (logs/'python-guest-code.stderr').write_bytes(attempt.stderr)
            record=re.search(rb'COMPACT_JOBS_RESULT status=([0-9]+) exited=([01]) exit=([0-9]+) steps=([0-9]+) syscalls=([0-9]+)',attempt.stderr)
            measured={key:int(value) for key,value in zip(
                ('status','exited','exit','steps','syscalls'),record.groups())} if record else None
            if measured:
                rip=re.search(rb' rip=([0-9a-f]+)',attempt.stderr)
                measured['last_rip_hex']=rip.group(1).decode() if rip else None
                denied=re.search(rb' unsupported_syscall=([0-9]+) unsupported_syscall_valid=([01])',attempt.stderr)
                measured['unsupported_syscall_nr']=int(denied.group(1)) if denied and denied.group(2)==b'1' else None
            passed=bool(measured and measured['status']==0 and measured['exited']==1
                        and measured['exit']==0 and
                        b'CLX_PYTHON_CODE_OK\n' in attempt.stdout)
            python_code_probe={'passed':passed,'actual':measured,
                               'runner_exit':attempt.returncode,
                               'expected_output':'CLX_PYTHON_CODE_OK',
                               'full_stdlib_workflow_qualified':False}
            if not passed:
                blockers.append('actual guest CPython -c code execution not yet qualified')
        if not success:blockers.append('guest smoke failed: '+str(actual if actual else {'runner_exit':guest.returncode}))
        records.append({'target':target,'version':version,'elf':info,'startup_libraries':libraries,'linux_reference_passed':reference_ok,'linux_reference_exit':reference.returncode,'linux_reference_output_excerpt':text[:2048],'linux_reference_metrics':metrics,'guest_smoke_passed':success,'guest_actual_result':actual,'guest_runner_exit':guest.returncode, 'guest_probe_args':guest_args,'guest_blockers':blockers,'python_code_probe':python_code_probe,'full_target_workflows_qualified':False})
    report={'schema':'compact-linux-target-profiles/v1','source_lock_sha256':build['source_lock_sha256'],'abi':build['abi'],'targets':records,'phase4_entry_ready':all(r['linux_reference_passed'] for r in records),'phase3_complete':False,'resource_qualified':False,'full_target_workflows_qualified':False,'limitations':['Reference smoke measurements are not full target workflow budgets','max_child_rss is not aggregate process-tree RAM','Target networking/certificate and PTY workflows remain unqualified','Guest failures are recorded, never promoted to successful measurements']}
    Path(output).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return 0 if report['phase4_entry_ready'] else 1
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',required=True);p.add_argument('--output',required=True);a=p.parse_args();raise SystemExit(main(a.directory,a.output))
