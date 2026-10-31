# SPDX-License-Identifier: AGPL-3.0-only
"""Reproduce the PE metadata baseline and W2 admission gaps; never execute PE."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from test_phase5_5_pe import fixture
PE=ROOT/'ryzova/compat/windows'

def variants():
    result={}
    for name,offset,fmt,value in (
        ('nonconsole-subsystem',0x98+68,'H',2),
        ('unaligned-image-base',0x98+24,'Q',0x140000001),
        ('noncanonical-image-base',0x98+24,'Q',0x8000000000000000),
        ('zero-size-of-headers',0x98+60,'I',0),
        ('raw-section-aliases-headers',0x188+20,'I',0),
        ('delay-import-directory',0x98+112+13*8,'II',(0x1000,8)),
    ):
        blob=fixture();values=value if isinstance(value,tuple) else (value,)
        struct.pack_into('<'+fmt,blob,offset,*values);result[name]=bytes(blob)
    return result

def audit():
    with tempfile.TemporaryDirectory() as d:
        directory=Path(d);binary=directory/'pe-probe'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',str(PE/'pe64.c'),str(PE/'pe64_probe.c'),'-o',str(binary)],check=True,capture_output=True,timeout=30)
        cases=[]
        for name,blob in {'baseline':bytes(fixture()),**variants()}.items():
            path=directory/(name+'.exe');path.write_bytes(blob)
            run=subprocess.run([str(binary),str(path)],capture_output=True,text=True,timeout=5)
            cases.append({'case':name,'fixture_sha256':hashlib.sha256(blob).hexdigest(),'probe_exit':run.returncode,'observed':run.stdout.strip(),'execution_attempted':False})
        return {'schema':'compact-windows-w1-audit/v1','scope':'metadata-only characterization; accepted variants are W2 admission blockers',
                'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (PE/'pe64.c',PE/'pe64.h',PE/'pe64_probe.c')},
                'cases':cases,'windows_execution_qualified':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);args=parser.parse_args()
    report=audit();text=json.dumps(report,indent=2)+'\n'
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(text)
    print(text,end='')
