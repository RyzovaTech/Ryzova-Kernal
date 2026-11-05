/* SPDX-License-Identifier: AGPL-3.0-only */
/* Static PE32+ x64 image-plan research. This NEVER loads DLLs or runs Windows. */
#include "pe64.h"
#include <string.h>
#define EXEC 0x20000000U
#define WRITE 0x80000000U
#define MAX_IMAGE (64U*1024U*1024U)
static uint16_t u16(const unsigned char *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1]<<8));
}
static uint32_t u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 |
           (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static uint64_t u64(const unsigned char *p)
{
    return (uint64_t)u32(p) | ((uint64_t)u32(p+4)<<32);
}
static int span(size_t size,uint64_t start,uint64_t n)
{
    return start <= (uint64_t)size && n <= (uint64_t)size-start;
}
static int aligned(uint32_t n,uint32_t multiple)
{
    return multiple!=0 && n%multiple==0;
}
int ryz_pe64_plan(const unsigned char *file,size_t size,RyzPe64Plan *plan)
{
    uint32_t header, pe, opt, sections, image_size, entry;
    uint32_t section_align, file_align, count_dirs, i, j;
    uint16_t count, optional;
    RyzPe64Plan p;
    int valid_entry=0;

    if (plan!=NULL)
        memset(plan,0,sizeof(*plan));
    if (file==NULL || plan==NULL || !span(size,0,0x40) ||
        file[0]!='M' || file[1]!='Z')
        return RYZ_PE64_BAD_HEADER;
    header=u32(file+0x3c);
    if (!span(size,header,24))
        return RYZ_PE64_OUT_OF_BOUNDS;
    pe=header;
    if (memcmp(file+pe,"PE\0\0",4)!=0)
        return RYZ_PE64_BAD_HEADER;
    if (u16(file+pe+4)!=0x8664)
        return RYZ_PE64_UNSUPPORTED;
    count=u16(file+pe+6);
    optional=u16(file+pe+20);
    if (count==0 || count>RYZ_PE64_MAX_SECTIONS || optional<240)
        return RYZ_PE64_UNSUPPORTED;
    /* Ignore DLLs; support EXE structure research only. */
    if ((u16(file+pe+22)&0x2000U)!=0)
        return RYZ_PE64_UNSUPPORTED;
    opt=pe+24;
    if (!span(size,opt,optional))
        return RYZ_PE64_OUT_OF_BOUNDS;
    if (u16(file+opt)!=0x20b)
        return RYZ_PE64_UNSUPPORTED;
    section_align=u32(file+opt+32);
    file_align=u32(file+opt+36);
    entry=u32(file+opt+16);
    image_size=u32(file+opt+56);
    if (section_align<4096 || section_align>(1U<<20) ||
        (section_align & (section_align-1U))!=0 ||
        file_align<512 || file_align>65536 ||
        (file_align & (file_align-1U))!=0 ||
        image_size==0 || image_size>MAX_IMAGE ||
        !aligned(image_size,section_align) ||
        entry>=image_size || entry==0)
        return RYZ_PE64_UNSAFE_MAPPING;
    count_dirs=u32(file+opt+108);
    if (count_dirs>16)
        return RYZ_PE64_UNSUPPORTED;
    /* If any imports, exception/unwind, base relocation, TLS or CLR are used,
       a future Windows API + loader design is required. */
    for (i=0;i<count_dirs;++i) {
        if (i==1 || i==3 || i==5 || i==9 || i==14) {
            if (u32(file+opt+112+8*i)!=0 ||
                u32(file+opt+116+8*i)!=0)
                return RYZ_PE64_UNSUPPORTED;
        }
    }
    sections=opt+optional;
    if (!span(size,sections,(uint64_t)count*40))
        return RYZ_PE64_OUT_OF_BOUNDS;
    memset(&p,0,sizeof(p));
    p.preferred_image_base=u64(file+opt+24);
    p.entry_rva=entry;
    p.image_size=image_size;
    p.section_count=count;
    if (p.preferred_image_base < 0x10000 ||
        p.preferred_image_base > UINT64_MAX-image_size)
        return RYZ_PE64_UNSAFE_MAPPING;
    for (i=0;i<count;++i) {
        const unsigned char *s=file+sections+40*i;
        uint32_t va=u32(s+12),virtual_bytes=u32(s+8);
        uint32_t raw_bytes=u32(s+16),raw_offset=u32(s+20);
        uint32_t flags=u32(s+36),map_size;
        RyzPe64Section *dst=&p.sections[i];
        if (virtual_bytes==0 || va==0 || (flags & (EXEC|WRITE))==(EXEC|WRITE) ||
            !aligned(va,section_align) || !aligned(raw_offset,file_align) ||
            (uint64_t)va+virtual_bytes>image_size)
            return RYZ_PE64_UNSAFE_MAPPING;
        if (raw_bytes>0 && !span(size,raw_offset,raw_bytes))
            return RYZ_PE64_OUT_OF_BOUNDS;
        map_size=virtual_bytes>raw_bytes?virtual_bytes:raw_bytes;
        if ((uint64_t)va+map_size>image_size)
            return RYZ_PE64_UNSAFE_MAPPING;
        for(j=0;j<i;++j) {
            const RyzPe64Section *prev=&p.sections[j];
            uint64_t prev_len=prev->virtual_bytes>prev->raw_bytes?
                 prev->virtual_bytes:prev->raw_bytes;
            if ((uint64_t)va < (uint64_t)prev->rva+prev_len &&
                (uint64_t)prev->rva < (uint64_t)va+map_size)
                return RYZ_PE64_UNSAFE_MAPPING;
        }
        dst->rva=va;
        dst->virtual_bytes=virtual_bytes;
        dst->raw_bytes=raw_bytes;
        dst->raw_offset=raw_offset;
        dst->flags=flags;
        if ((flags & EXEC)!=0 && entry>=va &&
            (uint64_t)entry-va < virtual_bytes &&
            (uint64_t)entry-va < raw_bytes)
            valid_entry=1;
    }
    if (!valid_entry)
        return RYZ_PE64_UNSAFE_MAPPING;
    *plan=p;
    return RYZ_PE64_OK;
}
