/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho64.h"
#include <string.h>
#define MAGIC 0xfeedfacfU
#define X86_64 0x01000007U
#define EXECUTE 2U
#define PIE 0x200000U
#define SEGMENT_64 0x19U
#define LC_MAIN 0x80000028U
#define LC_UUID 0x1bU
#define LC_BUILD_VERSION 0x32U
#define LC_VERSION_MIN_MACOSX 0x24U
#define VM_EXECUTE 4U
#define VM_WRITE 2U
#define MAX_SIZE (64U*1024U*1024U)
#define PAGE 4096U
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 |
           (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static uint64_t u64(const unsigned char *p) {
    return (uint64_t)u32(p) | ((uint64_t)u32(p+4)<<32);
}
static int span(size_t n,uint64_t a,uint64_t b) {
    return a <= (uint64_t)n && b <= (uint64_t)n-a;
}
static int overlap(uint64_t a,uint64_t al,uint64_t b,uint64_t bl) {
    return a < b+bl && b < a+al;
}
int ryz_macho64_plan(const unsigned char *image,size_t length,RyzMachoPlan *out) {
    RyzMachoPlan plan;
    uint32_t ncmd,commands,flags,index,count=0;
    uint64_t offset=32,entry_offset=0;
    int has_main=0,entry_found=0;
    if (out != NULL) memset(out,0,sizeof(*out));
    if (image==NULL || out==NULL || !span(length,0,32))
        return 1;
    if (u32(image)!=MAGIC)
        return 1;
    if (u32(image+4)!=X86_64 || u32(image+12)!=EXECUTE)
        return 2;
    flags=u32(image+24);
    if ((flags & PIE)!=0 || u32(image+28)!=0)
        return 2;
    ncmd=u32(image+16);commands=u32(image+20);
    if (ncmd==0 || ncmd>RYZ_MACHO_MAX_CMDS ||
        commands<8U*ncmd || commands>16384U ||
        !span(length,32,commands))
        return 3;
    memset(&plan,0,sizeof(plan));
    for(index=0;index<ncmd;++index) {
        uint32_t cmd,cmdsize;
        if (!span(length,offset,8) || offset-32>commands ||
            8U>commands-(offset-32))
            return 3;
        cmd=u32(image+(size_t)offset);
        cmdsize=u32(image+(size_t)offset+4);
        if (cmdsize<8 || (cmdsize&7U)!=0 ||
            !span(length,offset,cmdsize) ||
            cmdsize>commands-(offset-32))
            return 3;
        if (cmd==SEGMENT_64) {
            uint64_t va,vsize,fo,fs;
            uint32_t maxprot,initprot,sections,j;
            RyzMachoSegment *seg;
            if (cmdsize<72 || count==RYZ_MACHO_MAX_SEGMENTS)
                return 3;
            sections=u32(image+(size_t)offset+64);
            if (sections>16 || (uint64_t)sections*80U>cmdsize-72U)
                return 2;
            va=u64(image+(size_t)offset+24);
            vsize=u64(image+(size_t)offset+32);
            fo=u64(image+(size_t)offset+40);
            fs=u64(image+(size_t)offset+48);
            maxprot=u32(image+(size_t)offset+56);
            initprot=u32(image+(size_t)offset+60);
            if (vsize==0 || vsize>MAX_SIZE || va<0x10000 ||
                va>UINT64_MAX-vsize || fs>vsize ||
                (maxprot & ~7U)!=0 || (initprot & ~7U)!=0 ||
                (initprot & ~maxprot)!=0 ||
                ((maxprot|initprot)&(VM_EXECUTE|VM_WRITE))==(VM_EXECUTE|VM_WRITE))
                return 4;
            if (!span(length,fo,fs) || (va%PAGE)!=(fo%PAGE))
                return 3;
            for(j=0;j<count;++j)
                if (overlap(va,vsize,plan.segments[j].virtual_address,
                            plan.segments[j].virtual_bytes))
                    return 4;
            seg=&plan.segments[count++];
            seg->virtual_address=va;seg->virtual_bytes=vsize;
            seg->file_offset=fo;seg->file_bytes=fs;seg->protection=initprot;
        } else if (cmd==LC_MAIN) {
            if (has_main || cmdsize!=24 || u64(image+(size_t)offset+16)!=0)
                return 2;
            entry_offset=u64(image+(size_t)offset+8);
            has_main=1;
        } else if (cmd!=LC_UUID && cmd!=LC_BUILD_VERSION &&
                   cmd!=LC_VERSION_MIN_MACOSX) {
            return 2; /* Explicitly reject dylibs, dyld, codesign, threads. */
        }
        offset+=cmdsize;
    }
    if (offset!=32U+commands || !has_main || count==0)
        return 2;
    for(index=0;index<count;++index) {
        const RyzMachoSegment *s=&plan.segments[index];
        if ((s->protection&VM_EXECUTE) && entry_offset>=s->file_offset &&
            entry_offset-s->file_offset<s->file_bytes) {
            plan.entry=s->virtual_address+(entry_offset-s->file_offset);
            entry_found=1;
        }
    }
    if (!entry_found) return 4;
    plan.segment_count=count;
    *out=plan;
    return 0;
}
