# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only Win32 PE32+ import requirements inventory, NOT a launcher.

It classifies *direct* imports against Ryzova's declared, finite W1-W6
console/CRT surface. No DLL loading, host forwarding or arbitrary PE
execution. A fully recognized import table does NOT prove the app runnable.
"""
import argparse
import json
from pathlib import Path

FILE_LIMIT=64*1024*1024
MAX_MODULES=32
MAX_SYMBOLS=512
MAX_STRING=256
SUPPORTED_MACHINES={0x8664:"amd64",0xaa64:"arm64-classic"}


def field(data,offset,width):
    if (not isinstance(offset,int) or offset<0 or
            width not in (2,4,8) or offset>len(data) or width>len(data)-offset):
        raise ValueError("PE field outside bounded file")
    return int.from_bytes(data[offset:offset+width],"little")


def cstr(data,offset):
    if not isinstance(offset,int) or offset<0 or offset>=len(data):
        raise ValueError("PE string outside file")
    end=data.find(b"\0",offset,min(len(data),offset+MAX_STRING))
    if end<=offset:
        raise ValueError("missing bounded PE string terminator")
    data_segment=data[offset:end]
    if any(x<33 or x>126 for x in data_segment):
        raise ValueError("non-ASCII or control character in PE import name")
    return data_segment.decode("ascii")


def discover(data,plan):
    if (not isinstance(data,bytes) or len(data)<256 or len(data)>FILE_LIMIT or
            data[:2]!=b"MZ"):
        raise ValueError("untrusted PE input size/signature")
    if not isinstance(plan,dict) or plan.get("schema")!="compact-windows-plan/v1":
        raise ValueError("validated Windows plan required")
    pe=field(data,0x3c,4)
    if pe>len(data)-24 or data[pe:pe+4]!=b"PE\0\0":
        raise ValueError("not a valid PE signature")
    machine=field(data,pe+4,2)
    if machine not in SUPPORTED_MACHINES:
        raise ValueError("unsupported PE architecture; ARM64EC/X require separate ABI")
    sections=field(data,pe+6,2)
    opts=field(data,pe+20,2)
    if not 1<=sections<=96 or opts<112:
        raise ValueError("unbounded PE section or optional header count")
    optional=pe+24
    if optional>len(data) or opts>len(data)-optional:
        raise ValueError("PE optional header outside file")
    if field(data,optional,2)!=0x20b:
        raise ValueError("PE32+ required")
    count=field(data,optional+108,4)
    if count>16 or 112+count*8>opts:
        raise ValueError("bad PE directory count")
    sections_at=optional+opts
    if sections*40>len(data)-sections_at:
        raise ValueError("truncated PE sections")
    regions=[]
    for i in range(sections):
        off=sections_at+i*40
        virtual=field(data,off+12,4)
        raw_bytes=field(data,off+16,4)
        raw=field(data,off+20,4)
        if raw_bytes and (raw>len(data) or raw_bytes>len(data)-raw):
            raise ValueError("section outside input")
        regions.append((virtual,raw_bytes,raw))

    def image_rva(rva,length=1):
        if not rva or length<1:
            raise ValueError("missing RVA")
        for start,raw_length,raw_offset in regions:
            if rva>=start and rva-start<raw_length and length<=raw_length-(rva-start):
                return raw_offset+(rva-start)
        raise ValueError("import RVA not backed by image file")

    directory_rva=field(data,optional+112+8,4) if count>=2 else 0
    directory_bytes=field(data,optional+112+12,4) if count>=2 else 0
    approved=set(plan.get("hosted_api_subset",[]))
    seen=set()
    symbols=[]
    modules=[]
    if bool(directory_rva)!=bool(directory_bytes):
        raise ValueError("partial import directory")
    if directory_rva:
        if directory_bytes<20 or directory_bytes>MAX_MODULES*20+20:
            raise ValueError("unbounded import descriptors")
        base=image_rva(directory_rva,directory_bytes)
        completed=False
        for i in range(MAX_MODULES+1):
            if i*20+20>directory_bytes:
                break
            off=base+i*20
            oft=field(data,off,4)
            timestamp=field(data,off+4,4)
            forward=field(data,off+8,4)
            name_rva=field(data,off+12,4)
            ft=field(data,off+16,4)
            if (oft,timestamp,forward,name_rva,ft)==(0,0,0,0,0):
                completed=True
                break
            if i>=MAX_MODULES or not name_rva or not ft:
                raise ValueError("invalid import descriptor")
            name=cstr(data,image_rva(name_rva)).lower()
            if not name.endswith(".dll") or len(name)>128 or name in modules:
                raise ValueError("duplicate/invalid DLL name")
            modules.append(name)
            thunk_rva=oft or ft
            terminated=False
            for j in range(MAX_SYMBOLS+1):
                value=field(data,image_rva(thunk_rva+j*8,8),8)
                if not value:
                    terminated=True
                    break
                if j>=MAX_SYMBOLS or len(symbols)>=MAX_SYMBOLS:
                    raise ValueError("unbounded import thunk table")
                if value>>63:
                    # PE32+ ordinal import encoding uses only bit 63 and
                    # the low 16 bits. Bits 16..62 MUST be zero; treating
                    # forged high-bit RVAs as ordinals hides invalid input.
                    if value & 0x7fffffffffff0000:
                        raise ValueError("invalid PE32+ ordinal import reserved bits")
                    symbol="#"+str(value&0xffff)
                else:
                    if value>0xffffffff:
                        raise ValueError("unbounded import hint/name RVA")
                    hint=image_rva(value,2)
                    symbol=cstr(data,hint+2)
                ident=name+"!"+symbol
                if ident in seen:
                    raise ValueError("duplicate imported symbol")
                seen.add(ident)
                symbols.append(ident)
            if not terminated:
                raise ValueError("unterminated import thunk list")
        if not completed:
            raise ValueError("unterminated PE import descriptor array")

    supported=sorted(x for x in symbols if x in approved)
    missing=sorted(x for x in symbols if x not in approved)
    return {
        "schema":"compact-windows-import-inventory/v1",
        "architecture":SUPPORTED_MACHINES[machine],
        "direct_imports":len(symbols),
        "modules":modules,
        "supported_declared_imports":supported,
        "missing_or_ordinal_imports":missing,
        "declared_import_profile_covered":not missing,
        "guest_executable_verified":False,
        "general_windows_compatibility":False,
        "limitations":"Only direct PE imports; delay-load, transitive DLLs, TEB, resources, exceptions, ISA, runtime and hardware not qualified",
    }


if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pe",type=Path)
    ap.add_argument("--plan",type=Path,default=Path(__file__).resolve().parents[1]/
                    "ryzova/compact/windows-v1-plan.json")
    args=ap.parse_args()
    data=args.pe.read_bytes()
    plan=json.loads(args.plan.read_text())
    print(json.dumps(discover(data,plan),indent=2,sort_keys=True))
