# SPDX-License-Identifier: AGPL-3.0-only
"""W3 import fixture construction, bounded hosted launcher and Windows comparison."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
from compact_windows_w2 import ROOT, pe
APIS = ('GetStdHandle','WriteFile','ExitProcess','GetLastError','SetLastError',
        'GetCommandLineW','GetEnvironmentVariableW','VirtualAlloc','VirtualFree')
STDOUT = b'FLEX_WINDOWS_W3_OK\n'
STDERR = b'FLEX_WINDOWS_W3_STDERR\n'
COMMAND = 'flex.exe --w3-test "two words"'

def imported_pe(code, names=APIS, payload=b''):
    data = bytearray(0x400)
    struct.pack_into('<IIIII', data, 0, 0x2040, 0, 0, 0x2100, 0x20a0)
    data[0x100:0x10d] = b'KERNEL32.DLL\0'
    offset = 0x120
    for i, name in enumerate(names):
        entry = b'\0\0' + name.encode('ascii') + b'\0'
        data[offset:offset+len(entry)] = entry
        struct.pack_into('<Q', data, 0x40 + i*8, 0x2000+offset)
        struct.pack_into('<Q', data, 0xa0 + i*8, 0x2000+offset)
        offset = (offset + len(entry) + 1) & ~1
    data += payload
    blob = bytearray(pe(code,bytes(data)))
    struct.pack_into('<II',blob,0x98+112+8,0x2000,40)
    struct.pack_into('<II',blob,0x98+112+12*8,0x20a0,(len(names)+1)*8)
    return bytes(blob)

class Code:
    def __init__(self): self.bytes=bytearray()
    def emit(self, value): self.bytes += bytes.fromhex(value) if isinstance(value,str) else value; return self
    def call(self, name, names=APIS):
        at=0x1000+len(self.bytes)
        self.bytes += b'\xff\x15'+struct.pack('<i',0x20a0+names.index(name)*8-at-6)
        return self
    def lea(self, reg, rva):
        prefix={'rdx':b'\x48\x8d\x15','r9':b'\x4c\x8d\x0d','rcx':b'\x48\x8d\x0d'}[reg]
        at=0x1000+len(self.bytes);self.bytes+=prefix+struct.pack('<i',rva-at-7);return self

def console_fixture():
    code=Code().emit('4883ec28 b9f5ffffff').call('GetStdHandle').emit('4889c1')
    code.lea('rdx',0x2400).emit(b'\x41\xb8'+struct.pack('<I',len(STDOUT))).lea('r9',0x2440)
    code.emit('48c744242000000000').call('WriteFile').emit('b925000000').call('ExitProcess').emit('0f0b')
    return imported_pe(code.bytes,payload=STDOUT+bytes(128-len(STDOUT)))

def build(output):
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-pedantic','-O2',
                    '-fsanitize=undefined','-fno-sanitize-recover=all',
                    *[str(ROOT/'ryzova/compat/windows'/n) for n in ('loader.c','cpu.c','api.c','files.c','api_probe.c')],'-o',str(output)],check=True)
    return output

def execute(probe, image, command=COMMAND, env_name='FLEX_W3_PROBE', env_value='ready', consoles=3, api_mask=511, budget=262144):
    run=subprocess.run([str(probe),str(image),command,env_name,env_value,str(consoles),str(api_mask),str(budget)],capture_output=True,text=True,timeout=15)
    report=json.loads(run.stdout)
    if run.returncode!=(0 if report['status']==0 else 1):raise ValueError('exit/report mismatch')
    return report

def compare(probe,image,receipt,output):
    native=json.loads(Path(receipt).read_text(encoding='utf-8-sig'))
    digest=hashlib.sha256(Path(image).read_bytes()).hexdigest()
    source=hashlib.sha256((ROOT/'tests/fixtures/windows_w3_reference.c').read_bytes()).hexdigest()
    if (native.get('schema')!='compact-windows-w3-reference/v1' or
        native.get('source_commit')!=os.environ.get('GITHUB_SHA') or not os.environ.get('GITHUB_SHA') or
        native.get('source_sha256')!=source or native.get('executable_sha256')!=digest or
        native.get('architecture')!='X64' or not str(native.get('platform','')).startswith('Microsoft Windows ') or
        native.get('native_reference_passed') is not True or native.get('stdout')!=STDOUT.decode() or
        native.get('stderr')!=STDERR.decode() or native.get('exit_code')!=0x12345678):
        raise ValueError('Windows reference provenance/result mismatch')
    result=execute(probe,image)
    if (result.get('status')!=0 or result.get('exited') is not True or result.get('exit_kind')!=1 or
        result.get('exit_code')!=native['exit_code'] or result.get('stdout_hex')!=STDOUT.hex() or
        result.get('stderr_hex')!=STDERR.hex() or any(result.get('api_calls',{}).get(api,0)<1 for api in APIS)):
        raise ValueError(f'Windows/Flex W3 mismatch: {result}')
    result.update(schema='compact-windows-w3-comparison/v1',source_commit=os.environ['GITHUB_SHA'],
                  executable_sha256=digest,reference_match=True,
                  evidence_scope='hosted Flex Windows API subset; not native Flex kernel/QEMU')
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path);parser.add_argument('--receipt',type=Path)
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/compact-windows/w3')
    args=parser.parse_args();binary=build(args.output/'api-probe')
    if args.reference:print(json.dumps(compare(binary,args.reference,args.receipt,args.output/'comparison.json'),indent=2))
    else:
        image=args.output/'console.exe';image.write_bytes(console_fixture())
        print(json.dumps(execute(binary,image),indent=2))
