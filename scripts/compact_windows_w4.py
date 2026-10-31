# SPDX-License-Identifier: AGPL-3.0-only
"""Descriptor-rooted namespace launcher and identical Windows PE file-I/O check."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from compact_windows_w2 import ROOT
FILE_APIS=('CreateFileW','ReadFile','CloseHandle','SetFilePointerEx','GetFileSizeEx','FlushFileBuffers')
ALL_APIS=('GetStdHandle','WriteFile','ExitProcess','GetLastError','SetLastError','GetCommandLineW',
          'GetEnvironmentVariableW','VirtualAlloc','VirtualFree',*FILE_APIS)
REFERENCE_APIS=('GetStdHandle','WriteFile','ExitProcess','GetLastError',*FILE_APIS)
PAYLOAD=b'FLEX_WINDOWS_W4_FILE_OK\n'+bytes(3)+b'!'
STDOUT=b'FLEX_WINDOWS_W4_OK\n'

def build(output):
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([os.environ.get('CC','cc'),'-D_GNU_SOURCE','-DCW_FILES_PROBE','-std=c11','-Wall','-Wextra','-Werror','-pedantic','-O2',
                    '-fsanitize=undefined','-fno-sanitize-recover=all',
                    *[str(ROOT/'ryzova/compat/windows'/n) for n in ('loader.c','cpu.c','api.c','files.c','files_host.c','api_probe.c')],
                    '-o',str(output)],check=True)
    return output

def execute(probe,image,root,budget=262144,apis=32767):
    run=subprocess.run([str(probe),str(image),'flex.exe','FLEX_W4_PROBE','explicit','3',str(apis),str(budget),str(root)],capture_output=True,text=True,timeout=15)
    result=json.loads(run.stdout)
    if run.returncode!=(0 if result['status']==0 else 1):raise ValueError('exit/report mismatch')
    return result

def compare(probe,image,receipt,root,output):
    native=json.loads(Path(receipt).read_text(encoding='utf-8-sig'))
    digest=hashlib.sha256(Path(image).read_bytes()).hexdigest()
    source=hashlib.sha256((ROOT/'tests/fixtures/windows_w4_reference.c').read_bytes()).hexdigest()
    if (native.get('schema')!='compact-windows-w4-reference/v1' or not os.environ.get('GITHUB_SHA') or
        native.get('source_commit')!=os.environ['GITHUB_SHA'] or native.get('source_sha256')!=source or
        native.get('executable_sha256')!=digest or native.get('architecture')!='X64' or
        not str(native.get('platform','')).startswith('Microsoft Windows ') or native.get('native_reference_passed') is not True or
        native.get('stdout')!=STDOUT.decode() or native.get('stderr')!='' or native.get('exit_code')!=0x23456789 or
        native.get('file_sha256')!=hashlib.sha256(PAYLOAD).hexdigest()):
        raise ValueError('Windows file reference provenance/result mismatch')
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    if any(root.iterdir()):raise ValueError('comparison requires a fresh authorized root')
    result=execute(probe,image,root)
    file=root/'payload.bin'
    if (result.get('status')!=0 or result.get('exited') is not True or result.get('exit_kind')!=1 or
        result.get('exit_code')!=native['exit_code'] or result.get('stdout_hex')!=STDOUT.hex() or result.get('stderr_hex')!='' or
        result.get('provider_open_files')!=0 or any(result.get('api_calls',{}).get(api,0)<1 for api in REFERENCE_APIS) or
        not file.is_file() or file.is_symlink() or file.read_bytes()!=PAYLOAD):
        raise ValueError(f'Windows/Flex file reference mismatch: {result}')
    result.update(schema='compact-windows-w4-comparison/v1',source_commit=os.environ['GITHUB_SHA'],executable_sha256=digest,
                  file_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),reference_match=True,
                  evidence_scope='hosted Flex Windows namespace core with Linux descriptor transport; not native kernel/QEMU')
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True);parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/compact-windows/w4')
    args=parser.parse_args();probe=build(args.output/'file-probe')
    print(json.dumps(compare(probe,args.reference,args.receipt,args.output/'namespace-root',args.output/'comparison.json'),indent=2))
