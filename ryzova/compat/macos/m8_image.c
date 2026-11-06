/* SPDX-License-Identifier: AGPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#else
#include <string.h>
#endif
#include "m8_image.h"

typedef unsigned char Byte;
typedef unsigned int U32;
typedef unsigned long long U64;

enum {
    Segment64 = 0x19, Symtab = 2, Dysymtab = 0xb, Dylib = 0xc,
    Dyld = 0xe, Uuid = 0x1b, Signature = 0x1d, FunctionStarts = 0x26,
    DataInCode = 0x29, SourceVersion = 0x2a, BuildVersion = 0x32
};

#define Main 0x80000028U
#define Exports 0x80000033U
#define Chained 0x80000034U

static U32
u16(const Byte *p)
{
    return p[0] | (U32)p[1]<<8;
}

static U32
u32(const Byte *p)
{
    return u16(p) | u16(p+2)<<16;
}

static U64
u64(const Byte *p)
{
    return u32(p) | (U64)u32(p+4)<<32;
}

static void
put64(Byte *p, U64 value)
{
    unsigned int i;
    for(i=0; i<8; i++)
        p[i] = value>>(i*8);
}

static int
span(U64 total, U64 offset, U64 bytes)
{
    return offset<=total && bytes<=total-offset;
}

static int
within(U64 base, U64 total, U64 offset, U64 bytes)
{
    return offset>=base && span(total, offset-base, bytes);
}

static int
fixed(const Byte *name, const char *expected)
{
    unsigned int n = strlen(expected), i;
    if(memcmp(name, expected, n))
        return 0;
    for(i=n; i<16; i++)
        if(name[i])
            return 0;
    return 1;
}

static int
load_path(const Byte *cmd, U32 size, U32 minimum, const char *expected)
{
    U32 off = u32(cmd+8), len = strlen(expected)+1;
    return off>=minimum && span(size, off, len) && !memcmp(cmd+off, expected, len);
}

int
mac8_access(const Mac8Image *plan, U64 at, U32 bytes, U32 rights)
{
    unsigned int i;
    if(!plan || at<MAC8_BASE || !bytes || !rights || (rights&~7U))
        return 0;
    for(i=1; i<Mac8Segments; i++){
        const Mac8Segment *s = &plan->segments[i];
        if((s->protection&rights)==rights && within(s->offset, s->bytes, at-MAC8_BASE, bytes))
            return 1;
    }
    return 0;
}

/* Validate and retain the five-segment layout used by the M8 references.
 * __PAGEZERO is a guard region and never consumes backing storage. */
static int
segment(const Byte *cmd, U32 size, U32 length, U32 i, U64 *preferred,
        Mac8Image *plan, U32 *text_start, U32 *text_bytes)
{
    static const char *names[] = {"__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"};
    static const U32 rights[] = {0, 5, 3, 3, 1};
    U32 sections, j, flags, align;
    U64 va, vm, off, file, rva, previous, start, bytes;
    Mac8Segment *s;
    const Byte *sec;

    if(i>=Mac8Segments || size<72 || !fixed(cmd+8, names[i]))
        return 0;
    sections = u32(cmd+64);
    if(sections>32 || size!=72+sections*80 || u32(cmd+56)!=rights[i] ||
       u32(cmd+60)!=rights[i] || u32(cmd+68)!=(i==2?16U:0))
        return 0;
    va=u64(cmd+24); vm=u64(cmd+32); off=u64(cmd+40); file=u64(cmd+48);
    if(i==0){
        if(va || off || file || sections || vm<65536 || vm%plan->page ||
           vm>0x800000000000ULL-Mac8Limit)
            return 0;
        *preferred=vm;
        return 1;
    }
    s=&plan->segments[i];
    rva=plan->mapped_bytes;
    if(va!=*preferred+rva || off!=rva || !vm || vm%plan->page ||
       !span(Mac8Limit,rva,vm) || !file || file>vm || !span(length,off,file) ||
       (i<4 && file!=vm) || (i==4 && (off+file!=length || sections)))
        return 0;
    s->offset=rva; s->bytes=vm; s->file_bytes=file;
    s->protection=i==2?Mac8Read:rights[i];
    plan->mapped_bytes=rva+vm;
    previous=va;
    for(j=0; j<sections; j++){
        sec=cmd+72+j*80;
        start=u64(sec+32); bytes=u64(sec+40); flags=u32(sec+64)&255;
        align=u32(sec+52);
        if(!fixed(sec+16,names[i]) || start<previous || !within(va,vm,start,bytes) ||
           align>14 || start%((U64)1<<align) || u32(sec+56) || u32(sec+60))
            return 0;
        previous=start+bytes;
        if(flags==1){
            if(i!=3 || plan->bss_bytes || !bytes || u32(sec+48) || !fixed(sec,"__bss"))
                return 0;
            plan->bss=start-*preferred;
            plan->bss_bytes=bytes;
        }else{
            if((flags!=0 && flags!=2 && flags!=6 && flags!=8) ||
               !within(va,file,start,bytes) || u32(sec+48)!=off+(start-va))
                return 0;
        }
        if(i==1 && fixed(sec,"__text")){
            if(*text_bytes || flags || !bytes || (u32(sec+64)&0x80000000U)==0)
                return 0;
            *text_start=start-*preferred;
            *text_bytes=bytes;
        }
    }
    return 1;
}

static int
linkedit(const Mac8Image *plan, U32 off, U64 size)
{
    const Mac8Segment *s=&plan->segments[4];
    return within(s->offset,s->file_bytes,off,size);
}

static int
walk_chains(const Byte *image, U32 offset, U32 length, Mac8Image *plan, Byte *arena)
{
    const Byte *p=image+offset, *record;
    U32 starts, imports, symbols, i, name, at, record_end, rel, pages, page, start, slot;
    U32 previous, next, ordinal, bind_count=0, rebase_count=0, fixup_pages=0;
    U64 value, target;
    Byte referenced[Mac8Imports];
    const Mac8Segment *s;
    unsigned int j;

    memset(referenced,0,sizeof referenced);
    if(length<28 || u32(p) || u32(p+20)!=1 || u32(p+24))
        return 0;
    starts=u32(p+4); imports=u32(p+8); symbols=u32(p+12); i=u32(p+16);
    if(!i || i>Mac8Imports || starts<28 || !span(length,starts,24) ||
       imports<starts+24 || !span(length,imports,i*4) ||
       symbols<imports+i*4 || symbols>=length || u32(p+starts)!=Mac8Segments)
        return 0;
    plan->imports=i;
    for(i=0; i<plan->imports; i++){
        name=u32(p+imports+4*i);
        if((name&511)!=1 || !span(length-symbols,name>>9,2))
            return 0;
        at=symbols+(name>>9);
        if(p[at]!='_')
            return 0;
        for(j=0; j<128 && j<length-at && p[at+j]; j++)
            if(p[at+j]<33 || p[at+j]>126)
                return 0;
        if(j==128 || j==length-at)
            return 0;
        plan->names[i]=offset+at;
    }
    previous=starts+24;
    for(i=0; i<Mac8Segments; i++){
        rel=u32(p+starts+4+4*i);
        if(i!=2 && i!=3){
            if(rel)
                return 0;
            continue;
        }
        if(rel<24 || !span(imports-starts,rel,22) || starts+rel<previous)
            return 0;
        at=starts+rel;
        record=p+at;
        record_end=u32(record);
        pages=u16(record+20);
        s=&plan->segments[i];
        if(!pages || pages!=s->bytes/plan->page || record_end!=22+pages*2 ||
           !span(imports,at,record_end) || u16(record+4)!=plan->page ||
           u16(record+6)!=6 || u64(record+8)!=s->offset || u32(record+16))
            return 0;
        previous=at+record_end;
        for(page=0; page<pages; page++){
            start=u16(record+22+page*2);
            if(start==65535)
                continue;
            if(start&0x8000)
                return 0; /* One chain start per page. */
            fixup_pages++;
            for(;;){
                if(start%4 || !span(plan->page,start,8))
                    return 0;
                slot=s->offset+page*plan->page+start;
                if(!within(s->offset,s->file_bytes,slot,8) ||
                   (plan->bss_bytes && slot<plan->bss+plan->bss_bytes && plan->bss<slot+8))
                    return 0;
                value=u64(image+slot);
                next=(value>>51)&4095;
                if(value>>63){
                    ordinal=value&0xffffff;
                    if(ordinal>=plan->imports || ((value>>24)&0x7ffffffULL))
                        return 0;
                    target=MAC8_UNRESOLVED+16*ordinal;
                    referenced[ordinal]=1;
                    bind_count++;
                }else{
                    target=value&0xfffffffffULL;
                    if(((value>>36)&0x7fff) || !mac8_access(plan,MAC8_BASE+target,1,Mac8Read))
                        return 0;
                    target+=MAC8_BASE;
                    rebase_count++;
                }
                if(arena)
                    put64(arena+slot,target);
                if(!next)
                    break;
                if(next<2)
                    return 0;
                start+=next*4;
            }
        }
    }
    for(i=0; i<plan->imports; i++)
        if(!referenced[i])
            return 0;
    plan->binds=bind_count;
    plan->rebases=rebase_count;
    plan->fixup_pages=fixup_pages;
    return 1;
}

int
mac8_load(const Byte *image, U32 length, Byte *arena, U32 capacity, Mac8Image *out)
{
    Mac8Image plan;
    const Byte *cmd;
    U32 offset, end, count, kind, size, i, nsegments=0, text_start=0, text_bytes=0;
    U32 flags, seen=0, bit, fixoff=0, fixbytes=0;
    U64 preferred=0, entry=0;

    if(!image || !arena || !out || length<32 || length>Mac8Limit ||
       u32(image)!=0xfeedfacfU || u32(image+12)!=2 || u32(image+28))
        return 0;
    memset(&plan,0,sizeof plan);
    plan.cpu=u32(image+4);
    if(plan.cpu==0x01000007U && u32(image+8)==3)
        plan.page=4096;
    else if(plan.cpu==0x0100000cU && u32(image+8)==0)
        plan.page=16384;
    else return 0;
    flags=u32(image+24);
    count=u32(image+16);
    size=u32(image+20);
    if((flags&~0x200085U) || (flags&0x200004U)!=0x200004U ||
       !count || count>32 || size>plan.page-32 || !span(length,32,size))
        return 0;
    end=32+size;
    for(offset=32,i=0; i<count; i++,offset+=size){
        if(!span(end,offset,8))
            return 0;
        cmd=image+offset;
        kind=u32(cmd);
        size=u32(cmd+4);
        if(size<8 || size%8 || !span(end,offset,size))
            return 0;
        if(kind==Segment64){
            if(seen || !segment(cmd,size,length,nsegments++,&preferred,&plan,&text_start,&text_bytes))
                return 0;
            continue;
        }
        if(nsegments!=Mac8Segments)
            return 0;
        switch(kind){
        case Main:
            bit=1;
            if(size!=24 || u64(cmd+16))return 0;
            entry=u64(cmd+8);
            break;
        case Dylib:case Dyld:
            bit=kind==Dylib?2:4;
            if(size<(kind==Dylib?24:16) ||
               !load_path(cmd,size,kind==Dylib?24:12,
                          kind==Dylib?"/usr/lib/libSystem.B.dylib":"/usr/lib/dyld"))
                return 0;
            break;
        case Chained:case Exports:case FunctionStarts:case DataInCode:case Signature:
            bit=kind==Chained?8:kind==Exports?16:kind==FunctionStarts?32:kind==DataInCode?64:128;
            if(size!=16 || !linkedit(&plan,u32(cmd+8),u32(cmd+12)))return 0;
            if(kind==Chained){fixoff=u32(cmd+8); fixbytes=u32(cmd+12);}
            if(kind==Signature && (u32(cmd+12)<12 || memcmp(image+u32(cmd+8),"\xfa\xde\x0c\xc0",4)))
                return 0;
            break;
        case Uuid:case SourceVersion:
            bit=kind==Uuid?256:512;
            if(size!=(kind==Uuid?24:16))return 0;
            break;
        case BuildVersion:
            bit=1024;
            if(size<24 || u32(cmd+8)!=1 || (U64)u32(cmd+20)*8!=size-24)return 0;
            break;
        case Symtab:
            bit=2048;
            if(size!=24 || !linkedit(&plan,u32(cmd+8),(U64)u32(cmd+12)*16) ||
               !linkedit(&plan,u32(cmd+16),u32(cmd+20)))return 0;
            break;
        case Dysymtab:
            bit=4096;
            if(size!=80 || u32(cmd+32) || u32(cmd+36) || u32(cmd+40) ||
               u32(cmd+44) || u32(cmd+48) || u32(cmd+52) || u32(cmd+64) ||
               u32(cmd+68) || u32(cmd+72) || u32(cmd+76) ||
               !linkedit(&plan,u32(cmd+56),(U64)u32(cmd+60)*4))return 0;
            break;
        default:
            return 0;
        }
        if(seen&bit)return 0;
        seen|=bit;
    }
    if(offset!=end || nsegments!=Mac8Segments || (seen&15)!=15 ||
       (plan.cpu==0x0100000cU && (!(seen&128) || entry%4)) ||
       !within(text_start,text_bytes,entry,1) || text_start<end ||
       !plan.bss_bytes || capacity<plan.mapped_bytes ||
       !walk_chains(image,fixoff,fixbytes,&plan,0))
        return 0;
    plan.entry=entry;
    memset(arena,0,plan.mapped_bytes);
    memmove(arena,image,length);
    memset(arena+plan.bss,0,plan.bss_bytes);
    /* The second pass reads identical, caller-owned immutable input. */
    if(!walk_chains(image,fixoff,fixbytes,&plan,arena))
        return 0;
    *out=plan;
    return 1;
}
