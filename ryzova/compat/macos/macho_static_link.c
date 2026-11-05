/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_static_link.h"
#include <stdint.h>
#include <string.h>
#define MH_MAGIC_64 UINT32_C(0xfeedfacf)
#define CPU_X86_64 UINT32_C(0x01000007)
#define CPU_SUBTYPE_ALL UINT32_C(3)
#define MH_OBJECT UINT32_C(1)
#define LC_SEGMENT_64 UINT32_C(0x19)
#define LC_SYMTAB UINT32_C(0x02)
#define LC_DYSYMTAB UINT32_C(0x0b)
#define LC_BUILD_VERSION UINT32_C(0x32)
#define LC_VERSION_MIN_MACOSX UINT32_C(0x24)
#define LC_DATA_IN_CODE UINT32_C(0x29)
#define LC_UUID UINT32_C(0x1b)
#define MAX_NAMES 16U
#define MAX_RELOCS 8U
#define MAX_TEXT 1024U
#define OUTPUT_CODE_OFF 0x200U
#define BASE UINT64_C(0x100000000)
typedef struct Symbol {
    char name[64];
    uint32_t value;
    uint8_t defined;
} Symbol;
typedef struct Object {
    const unsigned char *data;
    size_t size;
    uint32_t text_offset, text_size, reloc_offset, reloc_count;
    uint32_t nsyms;
    Symbol symbols[MAX_NAMES];
} Object;

static uint32_t read32(const unsigned char *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|
           ((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t read64(const unsigned char *p) {
    return (uint64_t)read32(p)|((uint64_t)read32(p+4)<<32);
}
static void write32(unsigned char *p,uint32_t v) {
    p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);
    p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);
}
static void write64(unsigned char *p,uint64_t v) {
    write32(p,(uint32_t)v);write32(p+4,(uint32_t)(v>>32));
}
static int span(size_t length,uint64_t off,uint64_t n) {
    return off<=(uint64_t)length && n<=(uint64_t)length-off;
}
static int name_copy(const unsigned char *table,uint32_t bytes,
                     uint32_t offset,char to[64]) {
    unsigned int i;
    if(offset==0 || offset>=bytes)return 0;
    for(i=0;i<63;i++) {
        unsigned char ch;
        if(i>=bytes-offset)return 0;
        ch=table[offset+i];
        if(ch==0){if(i==0)return 0;to[i]=0;return 1;}
        if(!((ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||
             (ch>='0'&&ch<='9')||ch=='_'||ch=='.'||ch=='$'))
            return 0;
        to[i]=(char)ch;
    }
    return 0;
}
static int text_section(const unsigned char *section) {
    static const unsigned char name[6]={'_','_','t','e','x','t'};
    static const unsigned char seg[6]={'_','_','T','E','X','T'};
    uint32_t i;
    if(memcmp(section,name,6)!=0 || memcmp(section+16,seg,6)!=0)
        return 0;
    for(i=6;i<16;i++)
        if(section[i]!=0 || section[16+i]!=0)return 0;
    return 1;
}
static int parse(const unsigned char *image,size_t size,Object *o) {
    uint32_t ncmd,cmdbytes,seen_seg=0,seen_sym=0;
    uint32_t symoff=0,stroff=0,strbytes=0;
    uint64_t pos=32;
    if(image==NULL || size<32 || size>RYZ_MAC3C_OBJECT_MAX)
        return 1;
    if(read32(image)!=MH_MAGIC_64 || read32(image+4)!=CPU_X86_64 ||
       read32(image+8)!=CPU_SUBTYPE_ALL || read32(image+12)!=MH_OBJECT ||
       read32(image+24)!=0 || read32(image+28)!=0)
        return 1;
    ncmd=read32(image+16);cmdbytes=read32(image+20);
    if(ncmd<2 || ncmd>8 || cmdbytes>16384 ||
       cmdbytes<(uint64_t)ncmd*8U || !span(size,32,cmdbytes))
        return 1;
    memset(o,0,sizeof(*o));o->data=image;o->size=size;
    for(uint32_t i=0;i<ncmd;i++) {
        const unsigned char *p;
        uint32_t cmd,bytes;
        if(pos>32U+cmdbytes || !span(size,pos,8) ||
           (uint64_t)8>32U+cmdbytes-pos)return 1;
        p=image+(size_t)pos;cmd=read32(p);bytes=read32(p+4);
        if(bytes<8 || (bytes&7U)!=0 || bytes>32U+cmdbytes-pos ||
           !span(size,pos,bytes))return 1;
        if(cmd==LC_SEGMENT_64) {
            const unsigned char *s;
            uint32_t nsect;
            uint64_t secbytes;
            if(seen_seg++ || bytes!=152 || (nsect=read32(p+64))!=1)
                return 2;
            s=p+72;
            if(!text_section(s) || read64(s+32)!=0 ||
               (secbytes=read64(s+40))==0 || secbytes>MAX_TEXT ||
               read32(s+52)>4 || (read32(s+64)&255U)!=0)
                return 2;
            o->text_offset=read32(s+48);
            o->text_size=(uint32_t)secbytes;
            o->reloc_offset=read32(s+56);
            o->reloc_count=read32(s+60);
            if(o->reloc_count>MAX_RELOCS ||
               !span(size,o->text_offset,o->text_size) ||
               (o->reloc_count &&
                !span(size,o->reloc_offset,(uint64_t)o->reloc_count*8U)))
                return 1;
        }else if(cmd==LC_SYMTAB) {
            if(seen_sym++ || bytes!=24)return 1;
            symoff=read32(p+8);o->nsyms=read32(p+12);
            stroff=read32(p+16);strbytes=read32(p+20);
            if(o->nsyms==0 || o->nsyms>MAX_NAMES ||
               strbytes<2 || strbytes>4096 ||
               !span(size,symoff,(uint64_t)o->nsyms*16U) ||
               !span(size,stroff,strbytes))
                return 1;
        }else if(cmd==LC_DYSYMTAB) {
            if(bytes!=80)return 2;
        }else if(cmd==LC_BUILD_VERSION) {
            uint32_t ntools;
            if(bytes<24 || read32(p+8)!=1)return 2;
            ntools=read32(p+20);
            if(ntools>16 || bytes!=24U+8U*ntools)return 2;
        }else if(cmd==LC_VERSION_MIN_MACOSX) {
            if(bytes!=16)return 2;
        }else if(cmd==LC_DATA_IN_CODE) {
            if(bytes!=16 || !span(size,read32(p+8),read32(p+12)))
                return 2;
        }else if(cmd==LC_UUID) {
            if(bytes!=24)return 2;
        }else return 2;
        pos+=bytes;
    }
    if(pos!=32U+cmdbytes || seen_seg!=1 || seen_sym!=1 ||
       symoff<pos || stroff<pos ||
       ((uint64_t)symoff+(uint64_t)o->nsyms*16U>stroff &&
        (uint64_t)stroff+(uint64_t)strbytes>symoff))
        return 1;
    for(uint32_t i=0;i<o->nsyms;i++) {
        const unsigned char *sym=image+(size_t)symoff+(size_t)i*16U;
        const uint8_t typ=sym[4],sect=sym[5];
        const uint64_t value=read64(sym+8);
        Symbol *dest=&o->symbols[i];
        if(typ!=0x0fU && typ!=0x01U)return 2;
        if((typ==0x0fU && (sect!=1 || value>=o->text_size)) ||
           (typ==0x01U && (sect!=0 || value!=0)) ||
           (sym[6]!=0 || sym[7]!=0))
            return 2;
        if(!name_copy(image+(size_t)stroff,strbytes,read32(sym),dest->name))
            return 2;
        for(uint32_t j=0;j<i;j++)
            if(strcmp(dest->name,o->symbols[j].name)==0)
                return 2;
        dest->defined=(uint8_t)(typ==0x0fU);
        dest->value=(uint32_t)value;
    }
    return 0;
}
static int symbol_definition(const Object o[2],uint32_t index,
                             const char *name,uint32_t *position) {
    uint32_t count=0;
    for(uint32_t j=0;j<2;j++) {
        for(uint32_t k=0;k<o[j].nsyms;k++) {
            const Symbol *s=&o[j].symbols[k];
            if(s->defined && strcmp(s->name,name)==0) {
                if(++count>1)return 0; /* No duplicate/ambiguous definitions. */
                *position=(j==0?OUTPUT_CODE_OFF:index)+s->value;
            }
        }
    }
    return count==1;
}
int ryz_mac3_link2(const unsigned char *first,size_t first_len,
                   const unsigned char *second,size_t second_len,
                   unsigned char *result,size_t result_cap,
                   RyzMac3LinkReport *report) {
    Object objects[2],*o;
    uint32_t second_at,entry,relocated=0,resolved=0;
    unsigned char staged[RYZ_MAC3C_OUTPUT_BYTES];
    int status;
    if(report)memset(report,0,sizeof(*report));
    if(report==NULL || result==NULL ||
       result_cap<RYZ_MAC3C_OUTPUT_BYTES)return 1;
    status=parse(first,first_len,&objects[0]);
    if(status)return status;
    status=parse(second,second_len,&objects[1]);
    if(status)return status;
    second_at=OUTPUT_CODE_OFF+((objects[0].text_size+15U)&~15U);
    if(second_at>RYZ_MAC3C_OUTPUT_BYTES ||
       objects[1].text_size>RYZ_MAC3C_OUTPUT_BYTES-second_at)
        return 4;
    if(!symbol_definition(objects,second_at,"_ryz_entry",&entry) ||
       entry<OUTPUT_CODE_OFF ||
       entry>=OUTPUT_CODE_OFF+objects[0].text_size)return 3;
    memset(staged,0,sizeof(staged));
    memcpy(staged+OUTPUT_CODE_OFF,first+objects[0].text_offset,
           objects[0].text_size);
    memcpy(staged+second_at,second+objects[1].text_offset,
           objects[1].text_size);
    for(uint32_t obj_index=0;obj_index<2;obj_index++) {
        uint32_t code_offset=obj_index==0?OUTPUT_CODE_OFF:second_at;
        o=&objects[obj_index];
        for(uint32_t j=0;j<o->reloc_count;j++) {
            const unsigned char *rel=o->data+(size_t)o->reloc_offset+j*8U;
            uint32_t off=read32(rel),info=read32(rel+4),symbol=info&0x00ffffffU;
            uint32_t target;
            int64_t displacement;
            if(off>o->text_size || o->text_size-off<4 ||
               (info>>24 &1U)!=1U || (info>>25 &3U)!=2U ||
               (info>>27 &1U)!=1U || (info>>28 &15U)!=2U ||
               symbol>=o->nsyms || o->symbols[symbol].defined)
                return 2;
            if(read32(staged+code_offset+off)!=0)return 2;
            if(!symbol_definition(objects,second_at,
                                  o->symbols[symbol].name,&target))
                return 3;
            displacement=(int64_t)target-
                         (int64_t)(code_offset+off+4U);
            if(displacement<INT32_MIN || displacement>INT32_MAX)
                return 4;
            write32(staged+code_offset+off,(uint32_t)(int32_t)displacement);
            ++relocated;
            ++resolved;
        }
    }
    /* True MH_EXECUTE structure but only an original *synthetic test*
     * process with LC_MAIN and no dyld/libSystem/actual Darwin launch. */
    write32(staged,MH_MAGIC_64);
    write32(staged+4,CPU_X86_64);
    write32(staged+8,CPU_SUBTYPE_ALL);
    write32(staged+12,2U);
    write32(staged+16,2U);
    write32(staged+20,96U);
    write32(staged+24,0U);
    write32(staged+28,0U);
    write32(staged+32,LC_SEGMENT_64);
    write32(staged+36,72U);
    memcpy(staged+40,"__TEXT",6);
    write64(staged+56,BASE);
    write64(staged+64,4096U);
    write64(staged+72,0);
    write64(staged+80,4096U);
    write32(staged+88,5U);
    write32(staged+92,5U);
    write32(staged+96,0U);
    write32(staged+100,0U);
    write32(staged+104,0x80000028U);
    write32(staged+108,24U);
    write64(staged+112,entry);
    write64(staged+120,0U);
    memcpy(result,staged,sizeof(staged));
    report->object_count=2;
    report->applied_branch_relocations=relocated;
    report->resolved_external_symbols=resolved;
    report->output_code_bytes=(second_at-OUTPUT_CODE_OFF)+objects[1].text_size;
    report->entry_file_offset=entry;
    report->executed_native_guest=0;
    report->loaded_dylibs=0;
    return 0;
}
