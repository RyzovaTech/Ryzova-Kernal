/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_symbol_meta.h"
#include <stdint.h>
#include <string.h>
#define MH_MAGIC_64 UINT32_C(0xfeedfacf)
#define CPU_X86_64 UINT32_C(0x01000007)
#define MH_OBJECT UINT32_C(1)
#define LC_SEGMENT_64 UINT32_C(0x19)
#define LC_SYMTAB UINT32_C(0x02)
#define LC_DYSYMTAB UINT32_C(0x0b)
#define LC_BUILD_VERSION UINT32_C(0x32)
#define LC_VERSION_MIN_MACOSX UINT32_C(0x24)
#define LC_DATA_IN_CODE UINT32_C(0x29)
#define LC_UUID UINT32_C(0x1b)
#define M3B_MAX_BYTES (4U*1024U*1024U)

static uint32_t read32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|
           (uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t read64(const unsigned char *p) {
    return (uint64_t)read32(p)|((uint64_t)read32(p+4)<<32);
}
static int span(size_t length,uint64_t off,uint64_t amount) {
    return off<=length && amount<=length-off;
}
static int symbol_name(const unsigned char *base,uint32_t limit,
                       uint32_t index,char name[RYZ_MAC3_SYM_NAME_MAX]) {
    unsigned int i;
    if(index==0 || index>=limit)return 0;
    for(i=0;i<RYZ_MAC3_SYM_NAME_MAX;i++) {
        unsigned char ch;
        if(i>=limit-index)return 0;
        ch=base[index+i];
        if(ch==0) {
            if(i==0)return 0;
            name[i]=0;
            return 1;
        }
        if(!((ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||
             (ch>='0'&&ch<='9')||ch=='_'||ch=='.'||
             ch=='$'))
            return 0;
        name[i]=(char)ch;
    }
    return 0;
}

int ryz_mac3_symbols(const unsigned char *image,size_t length,
                     RyzMac3Symbols *out) {
    RyzMac3Symbols result;
    uint32_t ncmd,command_bytes,symoff=0,stroff=0,nsyms=0,strsize=0;
    uint32_t i,seen_sym=0,segments=0,version=0;
    uint64_t offset=32;
    if(out!=NULL)memset(out,0,sizeof(*out));
    if(image==NULL || out==NULL || length<32 || length>M3B_MAX_BYTES)
        return 1;
    if(read32(image)!=MH_MAGIC_64 || read32(image+4)!=CPU_X86_64 ||
       read32(image+8)!=3 || read32(image+12)!=MH_OBJECT ||
       read32(image+28)!=0)
        return 2;
    ncmd=read32(image+16);
    command_bytes=read32(image+20);
    if(ncmd<2 || ncmd>32 || command_bytes>16384 ||
       command_bytes<8U*ncmd || !span(length,32,command_bytes))
        return 3;
    memset(&result,0,sizeof(result));
    for(i=0;i<ncmd;i++) {
        const unsigned char *cmd;
        uint32_t opcode,command_size;
        if(offset>32U+command_bytes || !span(length,offset,8) ||
           8U>32U+command_bytes-offset)
            return 3;
        cmd=image+(size_t)offset;
        opcode=read32(cmd);
        command_size=read32(cmd+4);
        if(command_size<8 || (command_size&7U)!=0 ||
           command_size>32U+command_bytes-offset ||
           !span(length,offset,command_size))
            return 3;
        if(opcode==LC_SEGMENT_64) {
            uint32_t count;
            if(command_size<72 || segments++ || (count=read32(cmd+64))>16 ||
               command_size!=72U+80U*count)
                return 4;
            for(uint32_t j=0;j<count;j++) {
                const unsigned char *sect=cmd+72U+80U*j;
                uint32_t off=read32(sect+48),reloff=read32(sect+56);
                uint32_t nreloc=read32(sect+60);
                uint64_t sec_size=read64(sect+40);
                if(sec_size>UINT64_C(67108864) ||
                   nreloc>64U ||
                   (nreloc>0 && !span(length,reloff,(uint64_t)nreloc*8U)) ||
                   (uint64_t)result.relocation_count+nreloc>UINT32_MAX)
                    return 4;
                if((read32(sect+64)&255U)!=1U &&
                   !span(length,off,sec_size))
                    return 4;
                result.relocation_count+=nreloc;
            }
        }else if(opcode==LC_SYMTAB) {
            if(seen_sym++ || command_size!=24)return 4;
            symoff=read32(cmd+8);nsyms=read32(cmd+12);
            stroff=read32(cmd+16);strsize=read32(cmd+20);
            if(nsyms==0 || nsyms>RYZ_MAC3_SYM_MAX ||
               strsize==0 || strsize>16384 ||
               !span(length,symoff,(uint64_t)nsyms*16U) ||
               !span(length,stroff,strsize) ||
               ((uint64_t)symoff<=(uint64_t)stroff &&
                (uint64_t)stroff<(uint64_t)symoff+(uint64_t)nsyms*16U) ||
               ((uint64_t)stroff<=(uint64_t)symoff &&
                (uint64_t)symoff<(uint64_t)stroff+strsize))
                return 4;
        }else if(opcode==LC_DYSYMTAB) {
            if(command_size!=80)return 4;
        }else if(opcode==LC_VERSION_MIN_MACOSX) {
            if(version || command_size!=16)return 4;
            version=1;
        }else if(opcode==LC_BUILD_VERSION) {
            uint32_t ntools;
            if(version || command_size<24)return 4;
            ntools=read32(cmd+20);
            if(read32(cmd+8)!=1 || ntools>16 ||
               command_size!=24U+8U*ntools)return 4;
            version=1;
        }else if(opcode==LC_DATA_IN_CODE) {
            uint32_t fileoff,size;
            if(command_size!=16)return 4;
            fileoff=read32(cmd+8);size=read32(cmd+12);
            if(!span(length,fileoff,size))return 4;
        }else if(opcode==LC_UUID) {
            if(command_size!=24)return 4;
        }else{
            /* Linker options, bitcode, dylib injection, dyld bind/rebase,
             * and any unknown command must be qualified separately. */
            return 5;
        }
        offset+=command_size;
    }
    if(!seen_sym || segments!=1 || offset!=32U+command_bytes ||
       (uint64_t)symoff<offset || (uint64_t)stroff<offset)
        return 4;
    for(i=0;i<nsyms;i++) {
        const unsigned char *sym=image+(size_t)symoff+16U*i;
        RyzMac3Symbol *to=&result.symbols[i];
        uint32_t name_off=read32(sym);
        uint8_t type=sym[4],section=sym[5],masked=type&0x0eU;
        if((type&0xe0U)!=0 || (type&0x01U)==0 ||
           (masked!=0 && masked!=0x0eU) ||
           (masked==0 && (section!=0 || read64(sym+8)!=0)) ||
           (masked==0x0eU && section==0))
            return 4;
        if(!symbol_name(image+(size_t)stroff,strsize,name_off,to->name))
            return 4;
        for(uint32_t j=0;j<i;j++)
            if(strcmp(result.symbols[j].name,to->name)==0)
                return 4;
        to->kind=(uint8_t)(masked==0x0eU);
        to->section=section;
        to->value=read64(sym+8);
        if(to->kind)++result.defined_count;
        else ++result.undefined_count;
        ++result.count;
    }
    *out=result;
    return 0;
}
