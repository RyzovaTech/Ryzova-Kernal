/* SPDX-License-Identifier: AGPL-3.0-only */
#include "api.h"
#include <string.h>
static uint16_t u16(const unsigned char *p) { return (uint16_t)(p[0]|(uint16_t)p[1]<<8); }
static uint32_t u32(const unsigned char *p) { return (uint32_t)u16(p)|(uint32_t)u16(p+2)<<16; }
static uint64_t u64(const unsigned char *p) { return (uint64_t)u32(p)|(uint64_t)u32(p+4)<<32; }
static int span(uint64_t size,uint64_t off,uint64_t len) { return off<=size && len<=size-off; }
static uint32_t page(uint32_t n) { return (n+4095U)&~4095U; }
static int address_base(uint64_t base,uint32_t size) {
    return base>=65536 && !(base&65535) && base<UINT64_C(0x00007fff00000000) &&
        size<=UINT64_C(0x00007fff00000000)-base;
}
static int section_at(const CwPlan *p,uint32_t off,uint32_t size,int backed) {
    uint32_t i;
    for(i=0;i<p->count;i++) {
        const CwSection *s=&p->sections[i];
        if(off>=s->rva && span(backed?s->bytes:s->size,off-s->rva,size))return (int)i;
    }
    return -1;
}
/* Validate relocations using immutable file bytes, before touching the arena.
   Strict ordered DIR64 targets prevent duplicate patches and table self-mutation. */
static int relocations(const unsigned char *f,const CwPlan *p,unsigned char *image) {
    uint32_t pos=0,previous=0; int have=0,index;
    const unsigned char *table;
    if(!p->reloc_bytes)return p->base==p->preferred_base?CW_OK:CW_RELOCATION;
    index=section_at(p,p->reloc_rva,p->reloc_bytes,1);
    if(index<0)return CW_RELOCATION;
    table=f+p->sections[index].raw+(p->reloc_rva-p->sections[index].rva);
    while(pos<p->reloc_bytes) {
        uint32_t rva,bytes,k;
        if(!span(p->reloc_bytes,pos,8))return CW_RELOCATION;
        rva=u32(table+pos);bytes=u32(table+pos+4);
        if((rva&4095) || bytes<8 || (bytes&3) || !span(p->reloc_bytes,pos,bytes))return CW_RELOCATION;
        for(k=8;k<bytes;k+=2) {
            uint16_t entry=u16(table+pos+k);uint32_t target;
            if(!(entry>>12))continue;
            if((entry>>12)!=10)return CW_RELOCATION;
            if(rva>UINT32_MAX-(entry&4095U))return CW_RELOCATION;
            target=rva+(entry&4095U);
            if(section_at(p,target,8,1)<0 || (have && target<previous+8U) ||
               ((uint64_t)target<(uint64_t)p->reloc_rva+p->reloc_bytes &&
                (uint64_t)p->reloc_rva<(uint64_t)target+8))return CW_RELOCATION;
            if(p->iat_bytes && (uint64_t)target<(uint64_t)p->iat_rva+p->iat_bytes &&
               (uint64_t)p->iat_rva<(uint64_t)target+8)return CW_RELOCATION;
            previous=target;have=1;
            if(image) {
                uint64_t v=u64(image+target);unsigned int n;
                /* Address arithmetic follows 64-bit PE DIR64 addition. */
                v+=p->base-p->preferred_base;
                for(n=0;n<8;n++)image[target+n]=(unsigned char)(v>>(8*n));
            }
        }
        pos+=bytes;
    }
    return CW_OK;
}
/* Debug records are inert bytes: never load a PDB, follow a path or run code.
   Both RVA and raw file location must agree on a bounded backed payload. */
static int debug_metadata(const unsigned char *f,const CwPlan *p,uint32_t rva,uint32_t bytes) {
    uint32_t i;int index;const unsigned char *table;
    if(!bytes)return CW_OK;
    if(bytes%28 || bytes>28U*32U)return CW_HEADER;
    index=section_at(p,rva,bytes,1);if(index<0)return CW_HEADER;
    table=f+p->sections[index].raw+(rva-p->sections[index].rva);
    for(i=0;i<bytes;i+=28) {
        uint32_t length=u32(table+i+16),at=u32(table+i+20),raw=u32(table+i+24);
        if(u32(table+i))return CW_UNSUPPORTED;
        if(!length){if(at || raw)return CW_HEADER;continue;}
        index=section_at(p,at,length,1);
        if(index<0 || (uint64_t)p->sections[index].raw+at-p->sections[index].rva!=raw)return CW_HEADER;
    }
    return CW_OK;
}
static const unsigned char *backed(const unsigned char *f,const CwPlan *p,uint32_t rva,uint32_t size) {
    int i=section_at(p,rva,size,1);
    if(i<0)return NULL;
    return f+p->sections[i].raw+(rva-p->sections[i].rva);
}
static int ascii_name(const unsigned char *f,const CwPlan *p,uint32_t rva,char *out,uint32_t cap) {
    uint32_t n;
    for(n=0;n<cap;n++) {
        const unsigned char *c;
        if(rva>UINT32_MAX-n)return 0;
        c=backed(f,p,rva+n,1);if(!c || *c>127)return 0;
        out[n]=(char)*c;if(!*c)return n!=0;
    }
    return 0;
}
static int import_table(const unsigned char *f,CwPlan *p,uint32_t rva,uint32_t bytes) {
    const unsigned char *d,*end;uint32_t oft,ft,n,name_rva;char module[64],name[128];
    int i;uint32_t advertised_rva=p->iat_rva,advertised_bytes=p->iat_bytes;
    if(!bytes)return advertised_bytes?CW_HEADER:CW_OK;
    /* W3 loads no DLLs: one kernel32 descriptor plus one zero terminator only. */
    if(bytes!=40 || !(d=backed(f,p,rva,bytes)))return CW_HEADER;
    end=d+20;for(n=0;n<20;n++)if(end[n])return CW_UNSUPPORTED;
    oft=u32(d);ft=u32(d+16);name_rva=u32(d+12);
    if(u32(d+4) || u32(d+8) || !ft || (ft&7) || (oft&7) || !ascii_name(f,p,name_rva,module,sizeof(module)))return CW_UNSUPPORTED;
    for(n=0;module[n];n++)if(module[n]>='A' && module[n]<='Z')module[n]=(char)(module[n]+32);
    if(strcmp(module,"kernel32.dll"))return CW_UNSUPPORTED;
    if(!oft)oft=ft;
    for(n=0;n<=CW_MAX_IMPORTS;n++) {
        const unsigned char *lookup,*iat,*hint;uint64_t value;int api;
        if(oft>UINT32_MAX-n*8 || ft>UINT32_MAX-n*8)return CW_HEADER;
        lookup=backed(f,p,oft+n*8,8);iat=backed(f,p,ft+n*8,8);
        if(!lookup || !iat || u64(lookup)!=u64(iat))return CW_HEADER;
        value=u64(lookup);if(!value)break;
        if(n==CW_MAX_IMPORTS || value>UINT32_MAX-2)return CW_UNSUPPORTED;
        hint=backed(f,p,(uint32_t)value,2);
        if(!hint || !ascii_name(f,p,(uint32_t)value+2,name,sizeof(name)))return CW_HEADER;
        api=cw_api_id(name);if(api<0 || (p->api_mask&(1U<<api)))return CW_UNSUPPORTED;
        p->imports[n].iat=ft+n*8;p->imports[n].api=(uint32_t)api;p->api_mask|=1U<<api;
    }
    if(!n)return CW_HEADER;
    p->import_count=n;p->iat_rva=ft;p->iat_bytes=(n+1)*8;
    i=section_at(p,ft,p->iat_bytes,1);
    if(i<0 || !(p->sections[i].permissions&CW_R) || (p->sections[i].permissions&CW_X))return CW_MAPPING;
    if(advertised_bytes && (advertised_rva!=ft || advertised_bytes!=p->iat_bytes))return CW_HEADER;
    /* Distinct lookup and IAT arrays may not overlap. Resolution is immutable. */
    if(oft!=ft && (uint64_t)oft<(uint64_t)ft+p->iat_bytes && (uint64_t)ft<(uint64_t)oft+p->iat_bytes)return CW_HEADER;
    return CW_OK;
}
static int nonvolatile_register(unsigned int n) { return n==3 || (n>=5 && n<=7) || n>=12; }
/* Admit ordinary compiler unwind descriptions, not handlers or actual unwinding. */
static int unwind_metadata(const unsigned char *f,const CwPlan *p,uint32_t rva,uint32_t bytes) {
    uint32_t i,previous=0;const unsigned char *table;
    if(!bytes)return CW_OK;
    if(bytes%12 || bytes>12U*1024U || !(table=backed(f,p,rva,bytes)))return CW_HEADER;
    for(i=0;i<bytes;i+=12) {
        uint32_t start=u32(table+i),end=u32(table+i+4),at=u32(table+i+8),k=0,last;
        const unsigned char *u;int section;unsigned int count,frame;
        if(start>=end || (i && start<previous))return CW_HEADER;
        section=section_at(p,start,end-start,1);
        if(section<0 || !(p->sections[section].permissions&CW_X) || (at&3) || !(u=backed(f,p,at,4)))return CW_HEADER;
        if(u[0]!=1)return CW_UNSUPPORTED; /* version 1, flags 0: no handlers/chains */
        count=u[2];frame=u[3]&15;
        if(u[1]>end-start || (!frame && u[3]) || (frame && !nonvolatile_register(frame)) || !backed(f,p,at,4+((count+1)&~1U)*2))return CW_HEADER;
        last=u[1];
        while(k<count) {
            unsigned int offset=u[4+k*2],op=u[5+k*2]&15,info=u[5+k*2]>>4,extra=0;
            if(offset>last)return CW_HEADER;
            last=offset;
            switch(op) {
            case 0:if(!nonvolatile_register(info))return CW_HEADER;break;
            case 1:if(info>1)return CW_UNSUPPORTED;extra=info?2:1;break;
            case 2:break;
            case 3:if(info || !frame)return CW_HEADER;break;
            case 4:case 5:if(!nonvolatile_register(info))return CW_HEADER;extra=op==4?1:2;break;
            case 8:case 9:if(info<6)return CW_HEADER;extra=op==8?1:2;break;
            default:return CW_UNSUPPORTED;
            }
            if(k+extra>=count)return CW_HEADER;
            k+=1+extra;
        }
        previous=end;
    }
    return CW_OK;
}
int cw_plan(const unsigned char *f,size_t size,uint64_t base,CwPlan *out) {
    CwPlan p;uint32_t pe,opt,table,alignment,file_alignment,dirs,i,j,entry_ok=0;
    uint16_t optional,count,characteristics;
    uint32_t debug_rva=0,debug_bytes=0,imports_rva=0,imports_bytes=0,unwind_rva=0,unwind_bytes=0;
    if(out)memset(out,0,sizeof(*out));
    if(!f || !out || size>CW_MAX_FILE || !span(size,0,64) || f[0]!='M' || f[1]!='Z')return CW_HEADER;
    pe=u32(f+60);
    if(pe<64 || !span(size,pe,24) || memcmp(f+pe,"PE\0\0",4))return CW_HEADER;
    optional=u16(f+pe+20);count=u16(f+pe+6);characteristics=u16(f+pe+22);
    if(u16(f+pe+4)!=0x8664 || !count || count>CW_MAX_SECTIONS ||
       !(characteristics&2) || (characteristics&0x2000) || optional<240)return CW_UNSUPPORTED;
    /* Bounds above guarantee pe+24 is representable within the 4 MiB cap. */
    opt=pe+24;
    if(!span(size,opt,optional) || u16(f+opt)!=0x20b)return CW_HEADER;
    if(u16(f+opt+68)!=3)return CW_UNSUPPORTED;
    memset(&p,0,sizeof(p));
    alignment=u32(f+opt+32);file_alignment=u32(f+opt+36);dirs=u32(f+opt+108);
    p.preferred_base=u64(f+opt+24);p.base=base?base:p.preferred_base;
    p.entry=u32(f+opt+16);p.image_bytes=u32(f+opt+56);p.headers=u32(f+opt+60);p.count=count;
    table=opt+optional;
    if(alignment<4096 || alignment>(1U<<20) || (alignment&(alignment-1)) ||
       file_alignment<512 || file_alignment>65536 || (file_alignment&(file_alignment-1)) ||
       alignment<file_alignment || !p.image_bytes || p.image_bytes>CW_MAX_MEMORY-CW_STACK ||
       p.image_bytes%alignment || !address_base(p.preferred_base,p.image_bytes) ||
       !address_base(p.base,p.image_bytes) || !p.headers || p.headers%file_alignment ||
       p.headers>p.image_bytes || !span(size,0,p.headers) ||
       !span(p.headers,table,(uint64_t)count*40))return CW_MAPPING;
    if(dirs>16 || !span(optional,112,(uint64_t)dirs*8))return CW_HEADER;
    for(i=0;i<dirs;i++) {
        uint32_t rva=u32(f+opt+112+8*i),bytes=u32(f+opt+116+8*i);
        if(!rva && !bytes)continue;
        if(!rva || !bytes)return CW_HEADER;
        if(i==1){imports_rva=rva;imports_bytes=bytes;}
        else if(i==3){unwind_rva=rva;unwind_bytes=bytes;}
        else if(i==12){p.iat_rva=rva;p.iat_bytes=bytes;}
        else if(i==5){p.reloc_rva=rva;p.reloc_bytes=bytes;}
        else if(i==6){debug_rva=rva;debug_bytes=bytes;}
        else return CW_UNSUPPORTED; /* TLS, delay imports, bound imports, CLR, etc. */
    }
    if(p.reloc_bytes && (characteristics&1))return CW_RELOCATION;
    for(i=0;i<count;i++) {
        const unsigned char *s=f+table+i*40;CwSection *d=&p.sections[i];
        uint32_t virtual_size=u32(s+8),flags=u32(s+36);
        d->rva=u32(s+12);d->bytes=u32(s+16);d->raw=u32(s+20);
        d->size=virtual_size>d->bytes?virtual_size:d->bytes;
        d->permissions=((flags&0x40000000U)?CW_R:0)|((flags&0x80000000U)?CW_W:0)|((flags&0x20000000U)?CW_X:0);
        if(!d->size || d->size>p.image_bytes || d->rva%alignment || d->rva<page(p.headers) ||
           !span(p.image_bytes,d->rva,page(d->size)) ||
           (d->permissions&(CW_W|CW_X))==(CW_W|CW_X) ||
           (d->bytes && (d->raw<p.headers || d->raw%file_alignment || d->bytes%file_alignment || !span(size,d->raw,d->bytes))))return CW_MAPPING;
        for(j=0;j<i;j++) {
            CwSection *q=&p.sections[j];
            if((uint64_t)d->rva<(uint64_t)q->rva+page(q->size) &&
               (uint64_t)q->rva<(uint64_t)d->rva+page(d->size))return CW_MAPPING;
            if(d->bytes && q->bytes && (uint64_t)d->raw<(uint64_t)q->raw+q->bytes &&
               (uint64_t)q->raw<(uint64_t)d->raw+d->bytes)return CW_MAPPING;
        }
        if((d->permissions&CW_X) && p.entry>=d->rva &&
           span(virtual_size,p.entry-d->rva,1) && span(d->bytes,p.entry-d->rva,1))entry_ok=1;
    }
    if(!entry_ok)return CW_MAPPING;
    i=(uint32_t)import_table(f,&p,imports_rva,imports_bytes);if(i)return (int)i;
    i=(uint32_t)unwind_metadata(f,&p,unwind_rva,unwind_bytes);if(i)return (int)i;
    i=(uint32_t)debug_metadata(f,&p,debug_rva,debug_bytes);if(i)return (int)i;
    i=(uint32_t)relocations(f,&p,NULL);if(i)return (int)i;
    *out=p;return CW_OK;
}
unsigned char *cw_memory(CwMachine *m,uint64_t at,size_t n,unsigned int rights) {
    uint32_t i;
    unsigned char *service;
    if(!m || !m->image || !m->stack || !n || (rights!=CW_R && rights!=CW_W && rights!=CW_X))return NULL;
    service=cw_service_memory(m,at,n,rights);if(service)return service;
    if(at>=m->stack_base && span(CW_STACK,at-m->stack_base,n))
        return (rights&CW_X)?NULL:m->stack+(size_t)(at-m->stack_base);
    if(at<m->plan.base || !span(m->plan.image_bytes,at-m->plan.base,n))return NULL;
    at-=m->plan.base;
    if(rights==CW_W && m->plan.iat_bytes && at<(uint64_t)m->plan.iat_rva+m->plan.iat_bytes &&
       (uint64_t)m->plan.iat_rva<at+n)return NULL;
    if(span(m->plan.headers,at,n) && rights==CW_R)return m->image+(size_t)at;
    for(i=0;i<m->plan.count;i++) {
        CwSection *s=&m->plan.sections[i];
        if((s->permissions&rights)==rights && at>=s->rva && span(s->size,at-s->rva,n))return m->image+(size_t)at;
    }
    return NULL;
}
int cw_read(CwMachine *m,uint64_t at,unsigned char *out,size_t n,unsigned int rights) {
    unsigned char *p;
    if(!m || !m->image || !m->stack || !out || !n || (rights!=CW_R && rights!=CW_X))return CW_MEMORY;
    p=cw_memory(m,at,n,rights);
    if(!p)return CW_MEMORY;
    memcpy(out,p,n);return CW_OK;
}
int cw_write(CwMachine *m,uint64_t at,const unsigned char *in,size_t n) {
    unsigned char *p;
    if(!m || !m->image || !m->stack || !in || !n)return CW_MEMORY;
    p=cw_memory(m,at,n,CW_W);
    if(!p)return CW_MEMORY;
    memcpy(p,in,n);return CW_OK;
}
int cw_load(const unsigned char *f,size_t size,uint64_t base,unsigned char *arena,size_t capacity,CwMachine *m) {
    CwPlan p;uint32_t i;int status;
    if(!m)return CW_HEADER;
    memset(m,0,sizeof(*m));status=cw_plan(f,size,base,&p);
    if(status)return m->status=status;
    if(!arena || capacity<(size_t)p.image_bytes+CW_STACK)return m->status=CW_MEMORY;
    /* f and arena must not alias. Use uintptr_t to avoid unrelated-pointer UB. */
    if((uintptr_t)arena<=(uintptr_t)f ? (uintptr_t)f-(uintptr_t)arena<capacity : (uintptr_t)arena-(uintptr_t)f<size)return m->status=CW_MEMORY;
    memset(arena,0,(size_t)p.image_bytes+CW_STACK);
    memcpy(arena,f,p.headers);
    for(i=0;i<p.count;i++)if(p.sections[i].bytes)memcpy(arena+p.sections[i].rva,f+p.sections[i].raw,p.sections[i].bytes);
    status=relocations(f,&p,arena);if(status)return m->status=status;
    for(i=0;i<p.import_count;i++) {
        unsigned int n;uint64_t token=cw_api_token(p.imports[i].api);
        for(n=0;n<8;n++)arena[p.imports[i].iat+n]=(unsigned char)(token>>(n*8));
    }
    m->plan=p;m->image=arena;m->stack=arena+p.image_bytes;
    /* Guard page between image and the non-executable stack; another after it. */
    m->stack_base=p.base+p.image_bytes+4096;m->initial_sp=m->stack_base+CW_STACK-40;
    m->r[4]=m->initial_sp;m->ip=p.base+p.entry;m->flags=2;
    /* Synthetic trusted caller: return token is not mapped or executable.
       Only a top-level RET with balanced stack can finish the environment. */
    for(i=0;i<8;i++)m->stack[CW_STACK-40+i]=(unsigned char)(UINT64_MAX>>(i*8));
    return CW_OK;
}
