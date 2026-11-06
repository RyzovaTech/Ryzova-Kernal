# SPDX-License-Identifier: AGPL-3.0-only
"""Frozen compiler/CRT workloads and per-executable Windows/Flex comparisons."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
from compact_windows_w2 import ROOT,pe
from compact_windows_w4 import ALL_APIS as WIN_APIS
CRT_APIS=('memcpy','memmove','memset','memcmp','strlen','strcmp','strncmp','wcslen','malloc','calloc','realloc','free','_errno')
ALL_APIS=(*WIN_APIS,*CRT_APIS)
WORKLOADS={
 'buffers':{'case':1,'exit_code':0x34567891,'stdout':'FLEX_W5_BUFFERS_OK\n','apis':['memcpy','memmove','memset','memcmp','strlen','strcmp','strncmp','wcslen']},
 'heap':{'case':2,'exit_code':0x34567892,'stdout':'FLEX_W5_HEAP_OK\n','apis':['malloc','calloc','realloc','free','_errno','memset','memcmp']},
 'integer':{'case':3,'exit_code':0x34567893,'stdout':'FLEX_W5_INTEGER_OK\n','apis':[]},
 'divide-zero':{'case':4,'native_status':0xc0000094,'status':11,'stop':'integer-divide-error'},
 'access-fault':{'case':5,'native_status':0xc0000005,'status':6,'stop':'memory-fault'},
 'illegal-instruction':{'case':6,'native_status':0xc000001d,'status':7,'stop':'unsupported-opcode'},
}

def imported_pe_modules(code,modules,payload=b''):
    data=bytearray(0xc00);next_name=0x480;next_iat=0x280
    for mi,(module,exports) in enumerate(modules.items()):
        lookup=0x80+mi*0x100;module_at=0x400+mi*0x40;start_iat=next_iat
        raw=module.encode('ascii')+b'\0';data[module_at:module_at+len(raw)]=raw
        for i,name in enumerate(exports):
            raw=b'\0\0'+name.encode('ascii')+b'\0';data[next_name:next_name+len(raw)]=raw
            struct.pack_into('<Q',data,lookup+i*8,0x2000+next_name)
            struct.pack_into('<Q',data,next_iat,0x2000+next_name)
            next_iat+=8;next_name=(next_name+len(raw)+1)&~1
        next_iat+=8
        struct.pack_into('<IIIII',data,mi*20,0x2000+lookup,0,0,0x2000+module_at,0x2000+start_iat)
    data+=payload;blob=bytearray(pe(code,bytes(data)))
    struct.pack_into('<II',blob,0x98+112+8,0x2000,(len(modules)+1)*20)
    struct.pack_into('<II',blob,0x98+112+12*8,0x2280,next_iat-0x280)
    return bytes(blob)

def build(output):
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-pedantic','-O2','-fsanitize=undefined','-fno-sanitize-recover=all',
                    *[str(ROOT/'ryzova/compat/windows'/name) for name in ('loader.c','cpu.c','api.c','crt.c','sync_objects.c','files.c','api_probe.c')],'-o',str(output)],check=True)
    return output

def execute(probe,image,budget=262144):
    run=subprocess.run([str(probe),str(image),'flex.exe','FLEX_W5_PROBE','explicit','3',str((1<<28)-1),str(budget)],capture_output=True,text=True,timeout=15)
    result=json.loads(run.stdout)
    if run.returncode!=(0 if result['status']==0 else 1):raise ValueError('probe exit/report mismatch')
    return result

def compare(probe,directory,receipt,output):
    directory=Path(directory);native=json.loads(Path(receipt).read_text(encoding='utf-8-sig'))
    source=hashlib.sha256((ROOT/'tests/fixtures/windows_w5_reference.c').read_bytes()).hexdigest()
    if (native.get('schema')!='compact-windows-w5-reference/v1' or not os.environ.get('GITHUB_SHA') or native.get('source_commit')!=os.environ['GITHUB_SHA'] or
        native.get('source_sha256')!=source or native.get('architecture')!='X64' or not str(native.get('platform','')).startswith('Microsoft Windows ') or
        native.get('native_reference_passed') is not True or set(native.get('workloads',{}))!=set(WORKLOADS)):
        raise ValueError('Windows W5 suite provenance mismatch')
    results={}
    for name,spec in WORKLOADS.items():
        image=directory/(name+'.exe');original=native['workloads'][name]
        digest=hashlib.sha256(image.read_bytes()).hexdigest()
        if digest!=original.get('executable_sha256') or original.get('stderr')!='':raise ValueError('executable or stderr mismatch')
        result=execute(probe,image)
        if 'native_status' in spec:
            if original.get('exit_code')!=spec['native_status'] or original.get('stdout')!='' or result.get('status')!=spec['status'] or result.get('stop')!=spec['stop'] or result.get('exited') is not False or not result.get('guest_ip') or result.get('stdout_hex')!='':
                raise ValueError(f'fault classification mismatch {name}: {result}')
        else:
            if (original.get('exit_code')!=spec['exit_code'] or original.get('stdout')!=spec['stdout'] or result.get('status')!=0 or result.get('exited') is not True or
                result.get('exit_code')!=spec['exit_code'] or result.get('stdout_hex')!=spec['stdout'].encode().hex() or
                any(result.get('api_calls',{}).get(api,0)<1 for api in spec['apis'])):
                raise ValueError(f'compiler/CRT mismatch {name}: {result}')
        if result.get('stderr_hex')!='':raise ValueError('unexpected guest stderr')
        result.update(executable_sha256=digest,native_exit_code=original['exit_code']);results[name]=result
    final={'schema':'compact-windows-w5-comparison/v1','source_commit':os.environ['GITHUB_SHA'],'source_sha256':source,'workloads':results,
           'reference_match':True,'native_kernel_qualified':False,'evidence_scope':'hosted Windows compiler/selected CRT profile; no native Flex kernel/QEMU'}
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(final,indent=2)+'\n');return final

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--reference-dir',type=Path,required=True);parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/compact-windows/w5');args=parser.parse_args()
    binary=build(args.output/'runtime-probe');print(json.dumps(compare(binary,args.reference_dir,args.receipt,args.output/'comparison.json'),indent=2))
