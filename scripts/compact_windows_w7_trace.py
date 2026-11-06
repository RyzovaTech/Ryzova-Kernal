# SPDX-License-Identifier: AGPL-3.0-only
"""Execute the pinned jq bytes in an explicit fail-stop diagnostic profile."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from compact_windows_w7_jq import ROOT, INPUT, STDOUT, ARGS, SHA, verify_image, verify_reference, source_head


def import_names(image):
    pe=struct.unpack_from('<I',image,60)[0];opt=pe+24
    section_table=opt+struct.unpack_from('<H',image,pe+20)[0]
    sections=[struct.unpack_from('<IIII',image,section_table+i*40+8)
              for i in range(struct.unpack_from('<H',image,pe+6)[0])]
    def offset(rva,n=1):
        for virtual,at,size,raw in sections:
            if at<=rva and rva-at+n<=size:return raw+rva-at
        raise ValueError('unbacked import RVA')
    def string(rva,limit):
        raw=offset(rva);end=image.find(b'\0',raw,raw+limit)
        if end<0:raise ValueError('unterminated import name')
        return image[raw:end].decode('ascii')
    rva=struct.unpack_from('<I',image,opt+112+8)[0];result=[]
    for module_index in range(16):
        descriptor=struct.unpack_from('<IIIII',image,offset(rva+module_index*20,20))
        if not any(descriptor):return result
        lookup,_,_,module,iat=descriptor
        name=string(module,64)
        for index in range(256):
            value=struct.unpack_from('<Q',image,offset((lookup or iat)+index*8,8))[0]
            if not value:break
            result.append(dict(module=name,symbol=string(value+2,128),iat=iat+index*8))
        else:raise ValueError('unterminated imports')
    raise ValueError('unterminated modules')


def build(output):
    runtime=ROOT/'ryzova/compat/windows';output=Path(output)
    subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-pedantic','-D_GNU_SOURCE',
                    '-fsanitize=undefined','-fno-sanitize-recover=all','-DCW_TRACE_PROFILE',
                    '-DCW_FILES_PROBE','-DCW_READONLY_ROOT',
                    *[str(runtime/n) for n in ('loader.c','cpu.c','api.c','crt.c','sync_objects.c','files.c','files_host.c','api_probe.c')],
                    '-o',str(output)],check=True)
    return output


def api_grant_words():
    count = int(re.search(r'#define CW_API_COUNT (\d+)U',
                          (ROOT/'ryzova/compat/windows/api.h').read_text()).group(1))
    if not 0 < count <= 256:
        raise ValueError('registry exceeds permission words')
    return [(1 << max(0, min(32, count-word*32))) - 1 for word in range(8)]


def execute_image(binary,budget=16777216):
    binary=Path(binary).resolve();image=binary.read_bytes();verify_image(image)
    imports=import_names(image)
    words=api_grant_words()
    with tempfile.TemporaryDirectory() as work:
        path=Path(work);root=path/'work';root.mkdir();(root/'input.json').write_bytes(INPUT)
        probe=build(path/'probe')
        command=subprocess.list2cmdline(['jq.exe',*ARGS])
        run=subprocess.run([str(probe),str(binary),command,'RYZOVA_TRACE','explicit','3',
                            str(words[0]),str(budget),str(root),*map(str,words[1:])],capture_output=True,text=True,timeout=30)
        if run.stderr:raise ValueError('diagnostic stderr: '+run.stderr)
        result=json.loads(run.stdout)
        if run.returncode!=(0 if result['status']==0 else 1):raise ValueError('trace exit/report mismatch')
    slot=result.get('stop_import',0)
    if slot:
        if slot>len(imports):raise ValueError('trace import index out of bounds')
        result['unimplemented_import']=imports[slot-1]
    match = (
        result.get('status') == 0 and result.get('exited') is True
        and (result.get('exit_code'), result.get('stdout_hex'), result.get('stderr_hex')) == (0, STDOUT.hex(), '')
        and result.get('provider_read_bytes') == len(INPUT)
        and result.get('provider_write_bytes') == 0
        and result.get('provider_open_files') == 0
    )
    return dict(schema='compact-windows-w7-jq-trace/v1',sha256=SHA,input_sha256=hashlib.sha256(INPUT).hexdigest(),
                argv=ARGS,root_rights=9,execution=result,hosted_query_match=match,
                native_kernel_qualified=False,full_w7_complete=False)


def verify_startup(report):
    """Check the W7.1 startup checkpoint independently of the next blocker."""
    execution = report['execution']
    calls = execution.get('api_calls', {})
    milestones = ('_initterm_e', '_configure_wide_argv', '_initterm',
                  'WideCharToMultiByte', 'CreateSemaphoreA')
    if (execution.get('profile_flags') != 3 or not execution.get('executed') or
            execution.get('imports') != 217 or
            any(calls.get(name, 0) < 1 for name in milestones)):
        raise ValueError('pinned jq did not reach the W7.1 startup checkpoint')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path)
    parser.add_argument('--out',type=Path);parser.add_argument('--budget',type=int,default=16777216)
    parser.add_argument('--require-startup', action='store_true')
    parser.add_argument('--require-query', action='store_true')
    parser.add_argument('--reference', type=Path, help='Windows reference artifact directory')
    args=parser.parse_args()
    reference=verify_reference(args.reference) if args.reference else None
    report=execute_image(args.binary,args.budget)
    if reference:
        report['windows_reference']={k:reference[k] for k in ('source_commit','exit_code','stdout_hex','stderr_hex')}
    if args.out:
        report['source_commit']=source_head();args.out.mkdir(parents=True,exist_ok=True)
        (args.out/'jq-trace.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,sort_keys=True))
    if args.require_startup:
        verify_startup(report)
    if args.require_query and not report['hosted_query_match']:
        raise ValueError('pinned jq did not match the Windows query and file I/O receipt')
