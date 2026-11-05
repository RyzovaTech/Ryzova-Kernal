/* SPDX-License-Identifier: AGPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#else
#include <string.h>
#endif
#include "dynamic.h"

typedef unsigned char Byte;
typedef unsigned int U32;
typedef unsigned long long U64;
typedef struct Region Region;
struct Region {
    U32 offset, size;
};

enum {
    Segment64 = 0x19, Symtab = 2, Dysymtab = 0xb, LoadDylib = 0xc,
    LoadDyld = 0xe, Uuid = 0x1b,
    BuildVersion = 0x32, SourceVersion = 0x2a, FunctionStarts = 0x26,
    DataInCode = 0x29, CodeSignature = 0x1d
};

#define Main 0x80000028U
#define Exports 0x80000033U
#define Chained 0x80000034U

static U32
le32(const Byte *p)
{
    return (U32)p[0] | (U32)p[1]<<8 | (U32)p[2]<<16 | (U32)p[3]<<24;
}

static U32
le16(const Byte *p)
{
    return p[0] | (U32)p[1]<<8;
}

static U64
le64(const Byte *p)
{
    return le32(p) | (U64)le32(p+4)<<32;
}

static void
store64(Byte *p, U64 value)
{
    int i;
    for(i=0; i<8; i++)
        p[i] = value>>(8*i);
}

static int
span(U32 length, U64 start, U64 size)
{
    return start<=length && size<=length-start;
}

static int
in_linkedit(U32 length, U32 offset, U64 size, U32 page)
{
    return offset>=2*page && span(length, offset, size);
}

static int
fixed_name(const Byte *p, const char *name)
{
    unsigned int length = strlen(name);
    unsigned int i;
    if(memcmp(p, name, length)!=0)
        return 0;
    for(i=length; i<16; i++)
        if(p[i]!=0)
            return 0;
    return 1;
}

static int
exact_string(const Byte *p, U32 length, U32 offset, const char *value)
{
    unsigned int size = strlen(value)+1;
    return span(length, offset, size) && memcmp(p+offset, value, size)==0;
}

static int
segment_ok(const Byte *cmd, U32 size, U32 length, unsigned int index, U64 *preferred, U32 page)
{
    static const char *names[] = {"__PAGEZERO", "__TEXT", "__DATA_CONST", "__LINKEDIT"};
    static const U32 protection[] = {0, 5, 3, 1};
    U32 sections, i;
    U64 va, vm, off, file, section_va, section_size;
    const Byte *section;

    if(index>=4 || size<72 || !fixed_name(cmd+8, names[index]))
        return 0;
    sections = le32(cmd+64);
    if(sections>16 || size!=72+sections*80)
        return 0;
    va = le64(cmd+24);
    vm = le64(cmd+32);
    off = le64(cmd+40);
    file = le64(cmd+48);
    if(le32(cmd+56)!=protection[index] || le32(cmd+60)!=protection[index])
        return 0;
    if(index==0){
        if(va!=0 || vm<0x10000 || vm%page || vm>0x800000000000ULL-3*page ||
           off!=0 || file!=0 || sections!=0 || le32(cmd+68)!=0)
            return 0;
        *preferred = vm;
        return 1;
    }
    if(va!=*preferred+(index-1)*page || vm!=page || off!=(index-1)*page ||
       file==0 || file>vm || !span(length, off, file) ||
       (index<3 && file!=page) || (index==3 && (off+file!=length || sections!=0)) ||
       le32(cmd+68)!=(index==2 ? 0x10 : 0))
        return 0;
    for(i=0; i<sections; i++){
        section = cmd+72+i*80;
        section_va = le64(section+32);
        section_size = le64(section+40);
        if(!fixed_name(section+16, names[index]) || section_va<va ||
           !span(file, section_va-va, section_size) ||
           le32(section+48)!=off+(section_va-va) ||
           le32(section+52)>12 || le32(section+56)!=0 || le32(section+60)!=0)
            return 0;
    }
    return 1;
}

/* One page, one chain, one strong _write bind. Rebase targets are image offsets. */
static int
apply_fixups(const Byte *p, U32 length, Byte *data, MacDynamic *plan, U32 page)
{
    U32 starts, imports, symbols, section, offset, name, next;
    U64 pointer, target;
    unsigned int i;
    int bound = 0;

    if(length<28 || le32(p)!=0 || le32(p+16)!=1 || le32(p+20)!=1 || le32(p+24)!=0)
        return 0;
    starts = le32(p+4);
    imports = le32(p+8);
    symbols = le32(p+12);
    if(starts<28 || !span(length, starts, 20) || !span(length, imports, 4) ||
       symbols<imports+4 || symbols>=length || imports<starts+20)
        return 0;
    if(le32(p+starts)!=4 || le32(p+starts+4)!=0 ||
       le32(p+starts+8)!=0 || le32(p+starts+16)!=0)
        return 0;
    section = le32(p+starts+12);
    if(section<20 || !span(imports-starts, section, 24))
        return 0;
    section += starts;
    if(le32(p+section)!=24 || le16(p+section+4)!=page ||
       le16(p+section+6)!=6 || le64(p+section+8)!=page ||
       le32(p+section+16)!=0 || le16(p+section+20)!=1)
        return 0;
    name = le32(p+imports);
    if((name&0x1ff)!=1 || !exact_string(p+symbols, length-symbols, name>>9, "_write"))
        return 0;
    offset = le16(p+section+22);
    for(i=0; i<32; i++){
        if(offset%4 || !span(page, offset, 8))
            return 0;
        pointer = le64(data+offset);
        next = ((pointer>>51)&0xfff)*4;
        if(pointer>>63){
            if(bound || (pointer&0x7ffffffffffffULL)!=0)
                return 0;
            plan->write_slot = offset;
            store64(data+offset, MacWriteThunk);
            bound = 1;
        }else{
            target = pointer&0xfffffffffULL;
            if(((pointer>>36)&0x7fff)!=0 || target>=3*page)
                return 0;
            store64(data+offset, MacBase+target);
            plan->rebases++;
        }
        if(next==0)
            return bound;
        if(next<8)
            return 0;
        offset += next;
    }
    return 0;
}

int
mac_dynamic_load(const Byte *image, U32 length, Byte *text, Byte *data, MacDynamic *out, int arm64)
{
    U32 commands, end, offset, size, kind, bit, seen, i, ncmd, name, segments;
    U32 page = arm64 ? MacArmPage : MacPage;
    U64 preferred = 0;
    Region fixups = {0, 0};
    const Byte *cmd;
    MacDynamic plan = {0, 0, 0};

    if(length<=2*page || length>3*page || le32(image)!=0xfeedfacfU ||
       le32(image+4)!=(arm64 ? 0x0100000cU : 0x01000007U) ||
       le32(image+8)!=(arm64 ? 0 : 3) || le32(image+12)!=2 ||
       (le32(image+24)&~0x200085U)!=0 || (le32(image+24)&0x200004U)!=0x200004U ||
       le32(image+28)!=0)
        return 0;
    ncmd = le32(image+16);
    commands = le32(image+20);
    if(ncmd==0 || ncmd>32 || commands>page-32)
        return 0;
    end = 32+commands;
    seen = segments = 0;
    offset = 32;
    for(i=0; i<ncmd; i++, offset+=size){
        if(!span(end, offset, 8))
            return 0;
        cmd = image+offset;
        size = le32(cmd+4);
        kind = le32(cmd);
        if(size<8 || size%8 || !span(end, offset, size))
            return 0;
        if(kind==Segment64){
            if(!segment_ok(cmd, size, length, segments++, &preferred, page))
                return 0;
            continue;
        }
        switch(kind){
        case Main:
            bit = 1;
            if(size!=24 || le64(cmd+8)<end || le64(cmd+8)>=page || le64(cmd+16)!=0)
                return 0;
            plan.entry = le32(cmd+8);
            break;
        case LoadDylib:
            bit = 2;
            if(size<24)
                return 0;
            name = le32(cmd+8);
            if(name<24 || !exact_string(cmd, size, name, "/usr/lib/libSystem.B.dylib"))
                return 0;
            break;
        case LoadDyld:
            bit = 4;
            if(size<16)
                return 0;
            name = le32(cmd+8);
            if(name<12 || !exact_string(cmd, size, name, "/usr/lib/dyld"))
                return 0;
            break;
        case Chained:
            bit = 8;
            if(size!=16 || !in_linkedit(length, le32(cmd+8), le32(cmd+12), page))
                return 0;
            fixups.offset = le32(cmd+8);
            fixups.size = le32(cmd+12);
            break;
        case Exports:
        case FunctionStarts:
        case DataInCode:
            bit = kind==Exports ? 16 : kind==FunctionStarts ? 32 : 64;
            if(size!=16 || !in_linkedit(length, le32(cmd+8), le32(cmd+12), page))
                return 0;
            break;
        case CodeSignature:
            bit = 4096;
            if(!arm64 || size!=16 || le32(cmd+12)<12 ||
               !in_linkedit(length, le32(cmd+8), le32(cmd+12), page) ||
               memcmp(image+le32(cmd+8), "\xfa\xde\x0c\xc0", 4)!=0)
                return 0;
            break;
        case Uuid:
        case SourceVersion:
            bit = kind==Uuid ? 128 : 256;
            if(size!=(kind==Uuid ? 24 : 16))
                return 0;
            break;
        case BuildVersion:
            bit = 512;
            if(size<24 || le32(cmd+8)!=1 || (U64)le32(cmd+20)*8!=size-24)
                return 0;
            break;
        case Symtab:
            bit = 1024;
            if(size!=24 || !in_linkedit(length, le32(cmd+8), (U64)le32(cmd+12)*16, page) ||
               !in_linkedit(length, le32(cmd+16), le32(cmd+20), page))
                return 0;
            break;
        case Dysymtab:
            bit = 2048;
            if(size!=80 || le32(cmd+32) || le32(cmd+36) || le32(cmd+40) ||
               le32(cmd+44) || le32(cmd+48) || le32(cmd+52) ||
               !in_linkedit(length, le32(cmd+56), (U64)le32(cmd+60)*4, page) ||
               le32(cmd+64) || le32(cmd+68) || le32(cmd+72) || le32(cmd+76))
                return 0;
            break;
        default:
            return 0;
        }
        if(seen&bit)
            return 0;
        seen |= bit;
    }
    if(offset!=end || segments!=4 || (seen&15)!=15 || (arm64 && !(seen&4096)))
        return 0;
    memmove(data, image+page, page);
    if(!apply_fixups(image+fixups.offset, fixups.size, data, &plan, page))
        return 0;
    memmove(text, image, page);
    *out = plan;
    return 1;
}
