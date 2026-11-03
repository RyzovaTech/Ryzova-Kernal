/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_link_meta.h"
#include <stdint.h>
#include <string.h>

#define M3_MAGIC UINT32_C(0xfeedfacf)
#define M3_X86_64 UINT32_C(0x01000007)
#define M3_X86_64_ALL UINT32_C(3)
#define M3_EXECUTE UINT32_C(2)
#define M3_DYLIB UINT32_C(6)
#define M3_SEGMENT_64 UINT32_C(0x19)
#define M3_MAIN UINT32_C(0x80000028)
#define M3_LOAD_DYLIB UINT32_C(0x0c)
#define M3_ID_DYLIB UINT32_C(0x0d)
#define M3_LOAD_DYLINKER UINT32_C(0x0e)
#define M3_RPATH UINT32_C(0x8000001c)
#define M3_UUID UINT32_C(0x1b)
#define M3_BUILD_VERSION UINT32_C(0x32)
#define M3_VERSION_MACOS UINT32_C(0x24)
#define M3_LIMIT_CMDS 32U
#define M3_LIMIT_SEGMENTS 16U
#define M3_LIMIT_BYTES UINT64_C(67108864)
#define M3_TOP UINT64_C(0x0000800000000000)

static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|
           (uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t get64(const unsigned char *p) {
    return (uint64_t)get32(p)|((uint64_t)get32(p+4)<<32);
}
static int within(size_t size,uint64_t off,uint64_t n) {
    return off<=(uint64_t)size && n<=(uint64_t)size-off;
}
static int valid_path(const char *name) {
    size_t i,n=strlen(name),part=0;
    if(n<3 || n>=RYZ_MAC3_NAME_MAX)return 0;
    if(strncmp(name,"/usr/lib/",9)!=0 &&
       strncmp(name,"/System/Library/",16)!=0 &&
       strncmp(name,"@rpath/",7)!=0 &&
       strncmp(name,"@loader_path/",13)!=0 &&
       strncmp(name,"@executable_path/",17)!=0)
        return 0;
    for(i=0;i<n;i++) {
        unsigned char c=(unsigned char)name[i];
        if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
             (c>='0'&&c<='9')||c=='/'||c=='_'||c=='.'||
             c=='-'||c=='+'||c=='@'))
            return 0;
        if(c=='/') {
            if(i==0){part=i+1;continue;}
            if(i==part || (i-part==1 && name[part]=='.') ||
               (i-part==2 && name[part]=='.' && name[part+1]=='.'))
                return 0;
            part=i+1;
        }
    }
    if(part==n || (n-part==1 && name[part]=='.') ||
       (n-part==2 && name[part]=='.' && name[part+1]=='.'))
        return 0;
    return 1;
}
/* A tightly bounded, NUL-terminated string from one load command.
 * Command padding and link-name contents are not treated as authority.
 * Host filesystem queries are not made. */
static int copy_name(const unsigned char *cmd,uint32_t size,uint32_t at,
                     char dst[RYZ_MAC3_NAME_MAX]) {
    uint32_t i;
    if(at>=size)return 0;
    for(i=0;i<RYZ_MAC3_NAME_MAX;i++) {
        if(i>=size-at)return 0;
        if(cmd[at+i]==0) {
            if(i==0)return 0;
            dst[i]=0;
            return valid_path(dst);
        }
        dst[i]=(char)cmd[at+i];
    }
    return 0;
}
static int duplicate(const char *name,char arr[][RYZ_MAC3_NAME_MAX],
                     uint32_t used) {
    uint32_t i;
    for(i=0;i<used;i++)if(strcmp(name,arr[i])==0)return 1;
    return 0;
}
int ryz_mac3_scan(const unsigned char *image,size_t length,RyzMac3Manifest *out) {
    uint32_t type,ncmd,cmdbytes,i,segments=0,main_count=0,id_count=0,dyld=0;
    uint32_t version=0;
    uint64_t offset=32,entry_offset=0;
    struct {uint64_t address,size,file_offset,file_size;uint32_t protection;} ranges[M3_LIMIT_SEGMENTS];
    RyzMac3Manifest m;
    if(out!=NULL)memset(out,0,sizeof(*out));
    if(out==NULL || image==NULL || length<32 || length>RYZ_MAC3_MAX_INPUT)
        return 1;
    if(get32(image)!=M3_MAGIC || get32(image+4)!=M3_X86_64 ||
       get32(image+8)!=M3_X86_64_ALL)return 2;
    type=get32(image+12);
    if(type!=M3_EXECUTE && type!=M3_DYLIB)return 2;
    if(get32(image+28)!=0)return 2;
    ncmd=get32(image+16);
    cmdbytes=get32(image+20);
    if(ncmd==0 || ncmd>M3_LIMIT_CMDS || cmdbytes>16384 ||
       cmdbytes<8U*ncmd || !within(length,32,cmdbytes))
        return 3;
    memset(&m,0,sizeof(m));
    m.filetype=type;
    for(i=0;i<ncmd;i++) {
        const unsigned char *cmd;
        uint32_t op,bytes,at;
        if(offset<32 || offset>32U+cmdbytes ||
           !within(length,offset,8) ||
           (uint64_t)8>32U+cmdbytes-offset)
            return 3;
        cmd=image+(size_t)offset;
        op=get32(cmd);
        bytes=get32(cmd+4);
        if(bytes<8 || (bytes&7U)!=0 || bytes>32U+cmdbytes-offset ||
           !within(length,offset,bytes))
            return 3;
        if(op==M3_SEGMENT_64) {
            uint64_t va,vm,fo,fs;
            uint32_t mx,init,sec;
            if(bytes<72 || segments==M3_LIMIT_SEGMENTS)return 3;
            sec=get32(cmd+64);
            if(sec>16 || bytes!=72U+80U*sec)return 3;
            va=get64(cmd+24);vm=get64(cmd+32);
            fo=get64(cmd+40);fs=get64(cmd+48);
            mx=get32(cmd+56);init=get32(cmd+60);
            if(va<UINT64_C(0x10000) || va>=M3_TOP || !vm ||
               vm>M3_LIMIT_BYTES || vm>M3_TOP-va ||
               fs>vm || !within(length,fo,fs) ||
               (va&4095U)!=(fo&4095U) ||
               (mx&~7U)!=0 || (init&~7U)!=0 ||
               (init&~mx)!=0 || (mx&6U)==6U || (init&6U)==6U)
                return 4;
            for(uint32_t j=0;j<segments;j++) {
                uint64_t old=ranges[j].address,oldsz=ranges[j].size;
                if(va<old+oldsz && old<va+vm)return 4;
            }
            ranges[segments].address=va;
            ranges[segments].size=vm;
            ranges[segments].file_offset=fo;
            ranges[segments].file_size=fs;
            ranges[segments].protection=init;
            /* No section relocation/fixup bytes are interpreted here. */
            for(uint32_t j=0;j<sec;j++) {
                const unsigned char *sc=cmd+72U+80U*j;
                uint64_t sa=get64(sc+32),sz=get64(sc+40);
                uint32_t so=get32(sc+48),nr=get32(sc+60);
                if(memcmp(sc+16,cmd+8,16)!=0 || sa<va ||
                   sa-va>vm || sz>vm-(sa-va) || nr!=0 ||
                   get32(sc+52)>31U)
                    return 4;
                if((get32(sc+64)&255U)!=1U &&
                   ((uint64_t)so<fo || (uint64_t)so-fo>fs ||
                    sz>fs-((uint64_t)so-fo)))
                    return 4;
            }
            ++segments;
        }else if(op==M3_MAIN) {
            if(type!=M3_EXECUTE || main_count || bytes!=24 ||
               get64(cmd+16)!=0)return 4;
            entry_offset=get64(cmd+8);
            ++main_count;
        }else if(op==M3_LOAD_DYLIB || op==M3_ID_DYLIB) {
            char name[RYZ_MAC3_NAME_MAX]={0};
            if(bytes<32)return 4;
            at=get32(cmd+8);
            if(at<24 || !copy_name(cmd,bytes,at,name))return 4;
            if(op==M3_ID_DYLIB) {
                if(type!=M3_DYLIB || id_count++)return 4;
                memcpy(m.install_name,name,strlen(name)+1);
            }else{
                if(m.dependency_count==RYZ_MAC3_MAX_DEPENDENCIES ||
                   duplicate(name,m.dependencies,m.dependency_count))
                    return 4;
                memcpy(m.dependencies[m.dependency_count++],name,strlen(name)+1);
            }
        }else if(op==M3_RPATH) {
            char name[RYZ_MAC3_NAME_MAX]={0};
            if(bytes<16 || (at=get32(cmd+8))<12 ||
               !copy_name(cmd,bytes,at,name) ||
               m.rpath_count==RYZ_MAC3_MAX_RPATHS ||
               duplicate(name,m.rpaths,m.rpath_count))
                return 4;
            memcpy(m.rpaths[m.rpath_count++],name,strlen(name)+1);
        }else if(op==M3_LOAD_DYLINKER) {
            if(type!=M3_EXECUTE || dyld || bytes<16 ||
               (at=get32(cmd+8))<12 ||
               !copy_name(cmd,bytes,at,m.dyld) ||
               strcmp(m.dyld,"/usr/lib/dyld")!=0)
                return 4;
            dyld=1;
        }else if(op==M3_UUID) {
            if(bytes!=24)return 4;
        }else if(op==M3_VERSION_MACOS) {
            if(version || bytes!=16)return 4;
            version=1;
        }else if(op==M3_BUILD_VERSION) {
            uint32_t ntools;
            if(version || bytes<24)return 4;
            ntools=get32(cmd+20);
            if(get32(cmd+8)!=1 || ntools>16 ||
               bytes!=24U+8U*ntools)return 4;
            version=1;
        }else{
            /* No loader, symbol table, chained-fixup, code-signing, or
             * bind execution is admitted by the metadata-only profile. */
            return 5;
        }
        offset+=bytes;
    }
    if(offset!=32U+cmdbytes || segments==0 ||
       (type==M3_EXECUTE && !main_count) ||
       (type==M3_DYLIB && !id_count))
        return 4;
    if(type==M3_EXECUTE) {
        uint32_t entry_matches=0;
        for(i=0;i<segments;i++) {
            if((ranges[i].protection&4U)!=0 &&
               entry_offset>=ranges[i].file_offset &&
               entry_offset-ranges[i].file_offset<ranges[i].file_size)
                ++entry_matches;
        }
        if(entry_matches!=1)return 4;
    }
    m.segment_count=segments;
    m.dyld_seen=dyld;
    *out=m;
    return 0;
}
