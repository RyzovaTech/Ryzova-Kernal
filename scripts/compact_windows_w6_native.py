# SPDX-License-Identifier: AGPL-3.0-only
"""Native 6c/mk and source-built-kernel QEMU evidence for bounded Windows profiles."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from compact_windows_w2 import ROOT,pe
from compact_windows_w3 import STDOUT as API_OUT,STDERR as API_ERR
from compact_windows_w4 import PAYLOAD
from compact_windows_w5 import WORKLOADS
PIN='3c1b57c4b609525e76cb0abac48bc657f71187fd3506674dba4e49b42141729c'

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def standalone(data,text):return re.search(rb'(?:^|\r?\n)'+re.escape(text.encode())+rb'(?:\r?\n|$)',data) is not None

def references(fixtures,commit):
    fixtures=Path(fixtures);expected={}
    for key,source in [('w5','windows_w5_reference.c'),('w4','windows_w4_reference.c'),('w3','windows_w3_reference.c')]:
        receipt=json.loads((fixtures/(key+'.json')).read_text(encoding='utf-8-sig'))
        if receipt.get('schema')!=f'compact-windows-{key}-reference/v1' or receipt.get('source_commit')!=commit or receipt.get('native_reference_passed') is not True or receipt.get('source_sha256')!=digest(ROOT/'tests/fixtures'/source) or receipt.get('architecture')!='X64' or not str(receipt.get('platform','')).startswith('Microsoft Windows '):raise ValueError('Windows reference provenance')
        if key=='w5':
            if set(receipt['workloads'])!=set(WORKLOADS):raise ValueError('workload set')
            for name,spec in WORKLOADS.items():
                r=receipt['workloads'][name];code=spec.get('native_status',spec.get('exit_code'))
                if r['exit_code']!=code or r['stdout']!=spec.get('stdout','') or r['stderr']!='':raise ValueError('Windows workload result')
                expected[name]=r['executable_sha256']
        else:
            name='file' if key=='w4' else 'api';expected[name]=receipt['executable_sha256']
            if receipt['exit_code']!=(0x23456789 if key=='w4' else 0x12345678):raise ValueError('Windows API exit')
            if receipt.get('stdout')!=('FLEX_WINDOWS_W4_OK\n' if key=='w4' else API_OUT.decode()) or receipt.get('stderr')!=('' if key=='w4' else API_ERR.decode()):raise ValueError('Windows API output')
            if key=='w4' and receipt.get('file_sha256')!=hashlib.sha256(PAYLOAD).hexdigest():raise ValueError('Windows file bytes')
    limits=json.loads((fixtures/'limits.json').read_text(encoding='utf-8-sig'))
    if limits.get('source_commit')!=commit or limits.get('source_sha256')!=digest(ROOT/'tests/fixtures/windows_w6_limits.c') or limits.get('compiled_only') is not True or set(limits.get('images',{}))!={'heap-limit','io-limit','handle-limit','ramfs-io'}:raise ValueError('resource fixture provenance')
    expected.update(limits['images'])
    for name,sha in expected.items():
        if digest(fixtures/(name+'.exe'))!=sha:raise ValueError('PE artifact hash')
    return expected

def case_specs():
    cases={}
    for name,spec in WORKLOADS.items():cases[name]={'image':name,'status':spec.get('status',0),'code':spec.get('exit_code'),'out':spec.get('stdout','').encode().hex(),'err':''}
    cases.update(file={'image':'file','status':0,'code':103,'out':'','err':'','args':'-r /tmp/cw-local'},
                 api={'image':'api','status':0,'code':0x12345678,'out':API_OUT.hex(),'err':API_ERR.hex()},
                 loop={'image':'loop','status':8,'steps':1024,'out':'','err':'','args':'-b 1024'},
                 stack={'image':'stack','status':6,'out':'','err':''},
                 imagecap={'image':'imagecap','status':4,'admission':True},filecap={'image':'filecap','status':1,'admission':True},
                 readonly={'image':'file','status':0,'code':101,'out':'','err':'','args':'-r /tmp/cw-ro -R 9'},
                 unsynced={'image':'file','status':0,'code':103,'out':'','err':'','args':'-r /tmp/cw-unsynced'},
                 policy={'image':'buffers','status':10,'admission':True,'args':'-a 32767'})
    for name in ('heap-limit','io-limit','handle-limit','ramfs-io'):
        cases[name]={'image':name,'status':0,'code':37,'out':'','err':''}
    cases['handle-limit']['args']='-r /tmp/cw-local'
    cases['ramfs-io']['args']='-r /tmp/cw-ram'
    return cases

def parse_cases(log,specs):
    text=log.decode('utf-8','replace');results={}
    for name,spec in specs.items():
        section=re.search(r'(?:^|\r?\n)CW_CASE_'+re.escape(name)+r'_BEGIN\r?\n(.*?)\r?\nCW_CASE_'+re.escape(name)+r'_END(?:\r?\n|$)',text,re.S)
        if not section:raise ValueError('missing native case '+name)
        found=re.findall(r'(?m)^CW_NATIVE ([^\r\n]+)',section.group(1))
        if len(found)!=1:raise ValueError('missing/duplicate native receipt '+name)
        record=dict(re.findall(r'(\w+)=([^ ]+)',found[0]));record={k:int(v) if v.isdecimal() else v for k,v in record.items()}
        if record.get('status')!=spec['status']:raise ValueError(f'native status {name}: {record}')
        if spec.get('admission'):
            if record.get('executed')!=0 or record.get('admission')!=1:raise ValueError('false admission gate')
        else:
            if record.get('executed')!=1 or record.get('exited')!=(1 if spec['status']==0 else 0) or record.get('open')!=0 or not 0<record.get('guest',0)<=64*1024*1024:raise ValueError('native resource/exit receipt')
            for field in ('code','steps'):
                if spec.get(field) is not None and record.get(field)!=spec[field]:raise ValueError(f'native {field} {name}: {record}')
            for field,prefix in [('out','CW_OUT'),('err','CW_ERR')]:
                values=re.findall(r'(?m)^'+prefix+r' ([0-9a-f]*)\r?$',section.group(1))
                if values!=[spec[field]]:raise ValueError(f'native output {name}/{field}')
            if name=='heap-limit' and record.get('heap')!=1048576:raise ValueError('heap cap not exercised')
            if name=='handle-limit' and record.get('peak_handles')!=30:raise ValueError('handle cap not exercised')
            if name in ('file','unsynced') and record.get('error')!=50:raise ValueError('unsupported sync was hidden')
            if name=='readonly' and record.get('error')!=5:raise ValueError('read-only rights failure')
        results[name]=record
    return results

def session(image,commands,out,label,timeout,required=None):
    raw=bytearray();socketdir=tempfile.TemporaryDirectory(prefix='cw6-');ser=Path(socketdir.name)/'serial'
    cmd=['qemu-system-x86_64','-machine','pc,accel=tcg','-cpu','qemu64','-m','2048','-smp','2','-device','virtio-scsi-pci,id=scsi',
         '-drive',f'if=none,id=vd0,file={image},format=qcow2','-device','scsi-hd,drive=vd0','-device','virtio-net-pci,netdev=n0','-netdev','user,id=n0',
         '-vga','std','-display','none','-chardev',f'socket,id=uart,path={ser},server=on,wait=off','-serial','chardev:uart','-monitor','none','-no-reboot','-no-shutdown']
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);bootargs=login=False;stage=0;sent=False;completed=False
    with (out/(label+'-host.log')).open('wb') as host:
        proc=subprocess.Popen(cmd,stdout=host,stderr=subprocess.STDOUT)
        try:
            for _ in range(300):
                try:client.connect(str(ser));break
                except (FileNotFoundError,ConnectionRefusedError):
                    if proc.poll() is not None:raise RuntimeError('QEMU startup failed')
                    time.sleep(.1)
            else:raise RuntimeError('QEMU serial unavailable')
            client.setblocking(False);start=time.monotonic()
            while time.monotonic()-start<timeout:
                ready,_,_=select.select([client],[],[],.2)
                if ready:
                    data=client.recv(65536)
                    if data:raw.extend(data)
                tail=bytes(raw[-40000:])
                if b'bootargs is ' in tail and not bootargs:client.sendall(b'\r');bootargs=True
                if bootargs and (b'user[glenda]:' in tail or b'user:' in tail) and not login:client.sendall(b'glenda\r');login=True
                if login and b'term%' in tail and not sent:
                    client.sendall((commands[stage]+f'; echo CW6_STAGE_{stage}\r').encode());sent=True;print(label,'stage',stage,flush=True)
                if sent and standalone(tail,f'CW6_STAGE_{stage}'):
                    if required and stage in required and not standalone(tail,required[stage]):raise RuntimeError(label+' failed: '+required[stage]+' '+bytes(raw[-10000:]).decode('utf-8','replace'))
                    if stage==len(commands)-1:completed=True;break
                    # Require the shell prompt after the standalone marker.
                    marker=re.search(rb'(?:^|\r?\n)CW6_STAGE_'+str(stage).encode()+rb'\r?\n',tail)
                    if marker and b'term%' in tail[marker.end():]:stage+=1;sent=False
                if proc.poll() is not None:break
        finally:
            (out/(label+'-serial.log')).write_bytes(raw);proc.terminate()
            try:proc.wait(timeout=8)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
            client.close();socketdir.cleanup()
    if not completed:raise RuntimeError(f'{label} QEMU stage incomplete: {stage}; tail: '+bytes(raw[-6000:]).decode('utf-8','replace'))
    return bytes(raw)

def extract_kernel(image,out,expected):
    with tempfile.TemporaryDirectory(prefix='cw6-fat-') as directory:
        raw=Path(directory)/'disk.raw';kernel=Path(directory)/'kernel'
        subprocess.run(['qemu-img','convert','-O','raw','-S','4k',str(image),str(raw)],check=True)
        with raw.open('rb') as file:
            for offset in range(0,128*1024*1024,512):
                file.seek(offset);b=file.read(512)
                if len(b)!=512:break
                if b[:1] not in (b'\xeb',b'\xe9') or b[510:]!=b'\x55\xaa' or not (b[54:62].startswith(b'FAT') or b[82:90].startswith(b'FAT')):continue
                result=subprocess.run(['mcopy','-o','-i',f'{raw}@@{offset}','::9pc64',str(kernel)],capture_output=True)
                if result.returncode==0 and digest(kernel)==expected:return True
    raise ValueError('independent FAT kernel hash mismatch')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('image',type=Path);parser.add_argument('--fixtures',type=Path,required=True)
    args=parser.parse_args();out=ROOT/'artifacts/compact-windows/w6-native';out.mkdir(parents=True,exist_ok=True)
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip();hashes=references(args.fixtures,commit)
    for name,sha in hashes.items():(out/(name+'.exe')).write_bytes((args.fixtures/(name+'.exe')).read_bytes())
    synthetic={'loop':pe(b'\xeb\xfe'),'stack':pe(bytes.fromhex('4881ec00000200 48890424'))}
    large=bytearray(pe(b'\xc3'));import struct;struct.pack_into('<I',large,0x98+56,64*1024*1024);synthetic['imagecap']=bytes(large)
    synthetic['filecap']=pe(b'\xc3')+bytes(4*1024*1024)
    for name,data in synthetic.items():(out/(name+'.exe')).write_bytes(data);hashes[name]=digest(out/(name+'.exe'))
    archive=out/'source.tgz';sourcefiles=subprocess.check_output(['git','ls-files','sys/src/9','sys/include','amd64/include','ryzova/compat/windows'],cwd=ROOT,text=True).splitlines()
    with tarfile.open(archive,'w:gz',format=tarfile.USTAR_FORMAT) as tar:
        for name in sourcefiles:
            arc=name.replace('ryzova/compat/windows','sys/src/cmd/compact-windows',1);tar.add(ROOT/name,arcname=arc,recursive=False)
    archive_sha=digest(archive)
    handler=functools.partial(http.server.SimpleHTTPRequestHandler,directory=str(out));server=http.server.ThreadingHTTPServer(('127.0.0.1',8000),handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    build_commands=["ip/ipconfig -d ether /net/ether0; webfs",'hget http://10.0.2.2:8000/source.tgz > /tmp/cw-source.tgz; sha1sum -2 256 /tmp/cw-source.tgz',
      'cd /; mkdir -p /sys/src/cmd/compact-windows; tar xzf /tmp/cw-source.tgz',
      'cd /sys/src/cmd/compact-windows; mk install > /tmp/cw-build.log >[2=1] && echo CW_NATIVE_BUILD_OK; cat /tmp/cw-build.log',
      'cd /sys/src/9/pc64; mk > /tmp/cw-kernel.log >[2=1] && echo CW_KERNEL_BUILD_OK; tail -n 30 /tmp/cw-kernel.log',
      '9fs 9fat; cd /sys/src/9/pc64; cp 9pc64 /n/9fat/9pc64 && cmp 9pc64 /n/9fat/9pc64 && echo CW_KERNEL_COPY_OK; sha1sum -2 256 9pc64; sha1sum -2 256 /n/9fat/9pc64',
      'sha1sum -2 256 /amd64/bin/compact-windows; echo sync >> /srv/hjfs.cmd; sleep 3']
    buildlog=session(args.image,build_commands,out,'build',850,{3:'CW_NATIVE_BUILD_OK',4:'CW_KERNEL_BUILD_OK',5:'CW_KERNEL_COPY_OK'})
    for marker in ('CW_NATIVE_BUILD_OK','CW_KERNEL_BUILD_OK','CW_KERNEL_COPY_OK'):
        if not standalone(buildlog,marker):raise ValueError('native build failed: '+marker)
    if not re.search(rb'(?m)^'+archive_sha.encode()+rb'\s+/tmp/cw-source.tgz\r?$',buildlog):raise ValueError('guest source archive mismatch')
    kerneldigests=re.findall(rb'(?m)^([0-9a-f]{64})\s+(?:9pc64|/n/9fat/9pc64)\r?$',buildlog)
    if len(kerneldigests)!=2 or kerneldigests[0]!=kerneldigests[1]:raise ValueError('guest built/installed kernel hashes')
    kernel_sha=kerneldigests[0].decode();extract_kernel(args.image,out,kernel_sha)
    runtime_sha=re.findall(rb'(?m)^([0-9a-f]{64})\s+/amd64/bin/compact-windows\r?$',buildlog)
    if len(runtime_sha)!=1:raise ValueError('native runtime binary hash')
    cases=case_specs();commands=["cat '#Z/version'; cat '#Z/foundation'; cat '#Z/abi'; echo CW_IDENTITY_END",'ip/ipconfig -d ether /net/ether0; webfs',
      'mkdir -p /tmp/cw-local /tmp/cw-ro /tmp/cw-unsynced /tmp/cw-ram; ramfs -m /tmp/cw-ram',
      'sha1sum -2 256 /amd64/bin/compact-windows']
    for name in hashes:commands.append(f'hget http://10.0.2.2:8000/{name}.exe > /tmp/cw-{name}.exe; sha1sum -2 256 /tmp/cw-{name}.exe')
    for name,spec in cases.items():commands.append(f"echo CW_CASE_{name}_BEGIN; /amd64/bin/compact-windows {spec.get('args','')} /tmp/cw-{spec['image']}.exe; echo CW_CASE_{name}_END")
    commands+=['sha1sum -2 256 /tmp/cw-local/payload.bin /tmp/cw-ram/ram.bin',
      'test ! -e /tmp/cw-ro/payload.bin && test ! -e /tmp/cw-local/ram.bin && test ! -e /tmp/cw-ram/payload.bin && echo CW_NAMESPACE_ISOLATION_OK',
      'echo sync >> /srv/hjfs.cmd; sleep 3; echo CW_RUNTIME_DONE']
    log=session(args.image,commands,out,'fresh',420)
    if b'Ryzova Kernel 0.1.0-dev' not in log or b'9front-derived' not in log or not standalone(log,'CW_NAMESPACE_ISOLATION_OK'):raise ValueError('fresh kernel identity/namespace isolation')
    if runtime_sha[0] not in log:raise ValueError('fresh runtime binary mismatch')
    for name,sha in hashes.items():
        if not re.search(rb'(?m)^'+sha.encode()+rb'\s+/tmp/cw-'+name.encode()+rb'.exe\r?$',log):raise ValueError('guest PE hash '+name)
    records=parse_cases(log,cases)
    file_sha=hashlib.sha256(b'FLEX_WINDOWS_W4_FILE_OK\n').hexdigest();ram_sha=hashlib.sha256(bytes.fromhex('78563412')).hexdigest()
    for path,sha in [('/tmp/cw-local/payload.bin',file_sha),('/tmp/cw-ram/ram.bin',ram_sha)]:
        if not re.search(rb'(?m)^'+sha.encode()+rb'\s+'+path.encode()+rb'\r?$',log):raise ValueError('persistent/9P file mismatch')
    reboot=session(args.image,["cat '#Z/version'; sha1sum -2 256 /tmp/cw-local/payload.bin; echo CW_REBOOT_DONE"],out,'reboot',100)
    if b'Ryzova Kernel 0.1.0-dev' not in reboot or not re.search(rb'(?m)^'+file_sha.encode()+rb'\s+/tmp/cw-local/payload.bin\r?$',reboot):raise ValueError('reboot persistence mismatch')
    report={'schema':'compact-windows-w6-native/v1','source_commit':commit,'source_archive_sha256':archive_sha,'kernel_sha256':kernel_sha,'runtime_sha256':runtime_sha[0].decode(),
      'bootstrap_image_gzip_sha256':PIN,'cases':records,'fixture_sha256':hashes,'native_amd64_qemu_qualified':True,'native_9p_namespace_verified':True,
      'file_sha256':file_sha,'reboot_persistence_verified':True,'native_file_flush_qualified':False,'full_w6_complete':False,'physical_hardware_qualified':False,'arm64_windows_qualified':False,'general_windows_compatibility':False}
    (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True);server.shutdown()
if __name__=='__main__':main()
