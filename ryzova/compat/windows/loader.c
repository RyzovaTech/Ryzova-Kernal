/* SPDX-License-Identifier: AGPL-3.0-only */
#include "api.h"
#ifndef CW_PLAN9
#include <string.h>
#endif
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
/* TLS VAs belong to this image; no host pointer is ever followed. */
static int tls_address(const CwPlan *p,uint64_t va,uint32_t bytes,uint32_t *rva) {
    if(va<p->preferred_base || !span(p->image_bytes,va-p->preferred_base,bytes))return 0;
    *rva=(uint32_t)(va-p->preferred_base);return 1;
}
static int tls_location(const unsigned char *f,const CwPlan *p,uint32_t table,
                         uint32_t rva,uint32_t bytes,unsigned int rights,int backed) {
    int index=section_at(p,rva,bytes,backed);
    if(index<0 || p->sections[index].permissions!=rights ||
       !span(u32(f+table+(uint32_t)index*40+8),rva-p->sections[index].rva,bytes))return -1;
    return index;
}
static int tls_metadata(const unsigned char *f,CwPlan *p,uint32_t table,uint32_t rva,uint32_t bytes) {
    const unsigned char *d;uint64_t start,end,callbacks;uint32_t at,flags,i;int index;
    if(!bytes)return CW_OK;
    if(bytes!=40 || (rva&7))return CW_HEADER;
    index=tls_location(f,p,table,rva,40,CW_R,1);
    if(index<0)return CW_MAPPING;
    d=f+p->sections[index].raw+rva-p->sections[index].rva;
    start=u64(d);end=u64(d+8);callbacks=u64(d+24);flags=u32(d+36);
    if((flags&~0x00f00000U) || ((flags>>20)&15)>13)return CW_UNSUPPORTED;
    if(end<start || end-start>CW_TLS_LIMIT || u32(d+32)>CW_TLS_LIMIT-(end-start))return CW_BOUNDS;
    p->tls_bytes=(uint32_t)(end-start);p->tls_zero=u32(d+32);
    if(p->tls_bytes){
        if(!tls_address(p,start,p->tls_bytes,&p->tls_rva))return CW_MAPPING;
        index=section_at(p,p->tls_rva,p->tls_bytes,1);
        if(index<0 || !(p->sections[index].permissions&CW_R) || (p->sections[index].permissions&CW_X) ||
           !span(u32(f+table+(uint32_t)index*40+8),p->tls_rva-p->sections[index].rva,p->tls_bytes))return CW_MAPPING;
    }else if(start && !tls_address(p,start,0,&at))return CW_MAPPING;
    if(!tls_address(p,u64(d+16),4,&p->tls_index) || (p->tls_index&3) ||
       tls_location(f,p,table,p->tls_index,4,CW_R|CW_W,0)<0)return CW_MAPPING;
    if(p->iat_bytes && (uint64_t)p->tls_index<(uint64_t)p->iat_rva+p->iat_bytes &&
       (uint64_t)p->iat_rva<(uint64_t)p->tls_index+4)return CW_MAPPING;
    if(callbacks){
        if(!tls_address(p,callbacks,8,&at) || (at&7))return CW_MAPPING;
        for(i=0;i<=CW_TLS_CALLBACKS;i++){
            uint64_t callback;uint32_t target;
            index=tls_location(f,p,table,at+8*i,8,CW_R,1);
            if(index<0)return CW_MAPPING;
            callback=u64(f+p->sections[index].raw+at+8*i-p->sections[index].rva);
            if(!callback)break;
            if(i==CW_TLS_CALLBACKS)return CW_BOUNDS;
            if(!tls_address(p,callback,1,&target) || tls_location(f,p,table,target,1,CW_R|CW_X,1)<0)return CW_MAPPING;
            p->tls_callbacks[p->tls_count++]=target;
        }
    }
    p->tls_present=1;return CW_OK;
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
    const unsigned char *table;uint32_t modules,mi,seen=0,total=0,minimum=UINT32_MAX,maximum=0;
    uint32_t lookup_rva[16],iat_rva[16],iat_bytes[16],advertised_rva=p->iat_rva,advertised_bytes=p->iat_bytes;
    if(!bytes)return advertised_bytes?CW_HEADER:CW_OK;
    if((rva&3) || bytes<40 || !(table=backed(f,p,rva,bytes)))return CW_HEADER;
    if(bytes>65536)return CW_UNSUPPORTED;
    /* The directory can include ILTs, IATs and names after its terminator.
       Bound the descriptor scan independently of that trailing payload. */
    for(modules=0;modules<=16;modules++){
        if(!span(bytes,modules*20,20))return CW_HEADER;
        for(mi=0;mi<20;mi++)if(table[modules*20+mi])break;
        if(mi==20)break;
        if(modules==16)return CW_UNSUPPORTED;
    }
    if(!modules)return CW_HEADER;
    for(mi=0;mi<modules;mi++) {
        const unsigned char *d=table+mi*20;uint32_t oft=u32(d),ft=u32(d+16),n,k,module_id;char module[64],name[128];
        if(u32(d+4) || u32(d+8) || !ft || (ft&7) || (oft&7) || !ascii_name(f,p,u32(d+12),module,sizeof(module)))return CW_UNSUPPORTED;
        for(n=0;module[n];n++)if(module[n]>='A' && module[n]<='Z')module[n]=(char)(module[n]+32);
        module_id=(uint32_t)cw_api_module_id(module);
        if(!module_id || (seen&(1U<<module_id)))return CW_UNSUPPORTED;
        seen|=1U<<module_id;if(!oft)oft=ft;
        for(n=0;n<=CW_MAX_IMPORTS;n++) {
            const unsigned char *lookup,*iat;uint64_t value;int api;
            if(oft>UINT32_MAX-n*8 || ft>UINT32_MAX-n*8)return CW_HEADER;
            lookup=backed(f,p,oft+n*8,8);iat=backed(f,p,ft+n*8,8);
            if(!lookup || !iat || u64(lookup)!=u64(iat))return CW_HEADER;
            value=u64(lookup);if(!value)break;
            if(total==CW_MAX_IMPORTS || value>UINT32_MAX-2 || !backed(f,p,(uint32_t)value,2) || !ascii_name(f,p,(uint32_t)value+2,name,sizeof(name)))return CW_UNSUPPORTED;
            api=cw_api_id(name);
            if(api<0 || !cw_api_module_matches((unsigned int)api,module) || cw_plan_has_api(p,(unsigned int)api))return CW_UNSUPPORTED;
            p->imports[total].iat=ft+n*8;p->imports[total].api=(uint32_t)api;cw_plan_add_api(p,(unsigned int)api);total++;
        }
        if(!n)return CW_HEADER;
        lookup_rva[mi]=oft;iat_rva[mi]=ft;iat_bytes[mi]=(n+1)*8;
        if(((uint64_t)ft<(uint64_t)rva+(modules+1)*20 && (uint64_t)rva<(uint64_t)ft+iat_bytes[mi]) ||
           ((uint64_t)oft<(uint64_t)rva+(modules+1)*20 && (uint64_t)rva<(uint64_t)oft+iat_bytes[mi]))return CW_HEADER;
        {
            int section=section_at(p,ft,iat_bytes[mi],1);
            if(section<0 || !(p->sections[section].permissions&CW_R) || (p->sections[section].permissions&CW_X))return CW_MAPPING;
        }
        if(ft<minimum)minimum=ft;
        if(ft>UINT32_MAX-iat_bytes[mi])return CW_HEADER;
        if(ft+iat_bytes[mi]>maximum)maximum=ft+iat_bytes[mi];
        for(k=0;k<mi;k++)if((uint64_t)ft<(uint64_t)iat_rva[k]+iat_bytes[k] && (uint64_t)iat_rva[k]<(uint64_t)ft+iat_bytes[mi])return CW_HEADER;
    }
    for(mi=0;mi<modules;mi++) {
        uint32_t k;for(k=0;k<modules;k++)if((lookup_rva[mi]!=iat_rva[k] || mi!=k) &&
            (uint64_t)lookup_rva[mi]<(uint64_t)iat_rva[k]+iat_bytes[k] && (uint64_t)iat_rva[k]<(uint64_t)lookup_rva[mi]+iat_bytes[mi])return CW_HEADER;
    }
    p->import_count=total;p->iat_rva=minimum;p->iat_bytes=maximum-minimum;
    if(advertised_bytes && (advertised_rva!=minimum || advertised_bytes!=p->iat_bytes))return CW_HEADER;
    /* Protect the entire aggregate range, including alignment gaps. */
    if(section_at(p,minimum,p->iat_bytes,1)<0)return CW_HEADER;
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
int cw_plan_diagnostic(const unsigned char *f,size_t size,uint64_t base,CwPlan *out,
                       uint32_t *unsupported_directory) {
    CwPlan p;uint32_t pe,opt,table,alignment,file_alignment,dirs,i,j,entry_ok=0;
    uint16_t optional,count,characteristics;
    uint32_t debug_rva=0,debug_bytes=0,imports_rva=0,imports_bytes=0,unwind_rva=0,unwind_bytes=0;
    uint32_t resource_rva=0,resource_bytes=0,unsupported=UINT32_MAX;
    uint32_t tls_rva=0,tls_bytes=0;
    if(unsupported_directory)*unsupported_directory=UINT32_MAX;
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
        else if(i==2){resource_rva=rva;resource_bytes=bytes;}
        else if(i==3){unwind_rva=rva;unwind_bytes=bytes;}
        else if(i==12){p.iat_rva=rva;p.iat_bytes=bytes;}
        else if(i==5){p.reloc_rva=rva;p.reloc_bytes=bytes;}
        else if(i==6){debug_rva=rva;debug_bytes=bytes;}
        else if(i==9){tls_rva=rva;tls_bytes=bytes;}
        else if(unsupported==UINT32_MAX)unsupported=i;
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
    /* Resources are opaque guest bytes. Never follow resource entries or
       expose Win32 resource APIs under this execution profile. */
    if(resource_bytes){
        int index=section_at(&p,resource_rva,resource_bytes,1);
        const unsigned char *header,*root;
        const CwSection *section;
        uint32_t delta,entries;
        if(index<0 || resource_bytes<16 || (resource_rva&3))return CW_MAPPING;
        section=&p.sections[index];
        header=f+table+(uint32_t)index*40;
        delta=resource_rva-section->rva;
        if(section->permissions!=CW_R || memcmp(header,".rsrc\0\0",8) ||
           !span(u32(header+8),delta,resource_bytes))return CW_MAPPING;
        root=f+section->raw+delta;
        entries=(uint32_t)u16(root+12)+u16(root+14);
        if(!span(resource_bytes,16,(uint64_t)entries*8))return CW_HEADER;
    }
    if(unsupported!=UINT32_MAX){
        if(unsupported_directory)*unsupported_directory=unsupported;
        return CW_UNSUPPORTED;
    }
    i=(uint32_t)tls_metadata(f,&p,table,tls_rva,tls_bytes);if(i)return (int)i;
    i=(uint32_t)import_table(f,&p,imports_rva,imports_bytes);if(i)return (int)i;
    /* The aggregate IAT may have been inferred when directory 12 was absent. */
    if(p.tls_present && p.iat_bytes && (uint64_t)p.tls_index<(uint64_t)p.iat_rva+p.iat_bytes &&
       (uint64_t)p.iat_rva<(uint64_t)p.tls_index+4)return CW_MAPPING;
    i=(uint32_t)unwind_metadata(f,&p,unwind_rva,unwind_bytes);if(i)return (int)i;
    i=(uint32_t)debug_metadata(f,&p,debug_rva,debug_bytes);if(i)return (int)i;
    i=(uint32_t)relocations(f,&p,NULL);if(i)return (int)i;
    *out=p;return CW_OK;
}
int cw_plan(const unsigned char *f,size_t size,uint64_t base,CwPlan *out) {
    return cw_plan_diagnostic(f,size,base,out,NULL);
}
static void store64(unsigned char *p,uint64_t value) {
    unsigned int i;for(i=0;i<8;i++)p[i]=(unsigned char)(value>>(8*i));
}
static void bootstrap(CwMachine *m) {
    uint64_t token=UINT64_MAX;
    m->r[4]=m->initial_sp;
    if(m->tls_next<m->plan.tls_count){
        m->ip=m->plan.base+m->plan.tls_callbacks[m->tls_next++];
        m->r[1]=m->plan.base;m->r[2]=1;m->r[8]=0;token=CW_TLS_RETURN;
    }else {
        m->ip=m->plan.base+m->plan.entry;
        m->r[0]=m->r[1]=m->r[2]=m->r[8]=m->r[9]=m->r[10]=m->r[11]=0;
    }
    store64(m->stack+CW_STACK-40,token);
    memset(m->stack+CW_STACK-32,0,32);
}
int cw_bootstrap_return(CwMachine *m,uint64_t token,uint64_t sp) {
    if(sp!=m->initial_sp)return CW_ABI;
    if(token==CW_TLS_RETURN){
        if(!m->tls_next || m->tls_next>m->plan.tls_count)return CW_ABI;
        /* Mark startup finished so an entry point cannot replay a callback return. */
        if(m->tls_next==m->plan.tls_count){bootstrap(m);m->tls_next=m->plan.tls_count+1;}
        else bootstrap(m);
        return CW_OK;
    }
    if(token!=UINT64_MAX || (m->plan.tls_count && m->tls_next<=m->plan.tls_count))return CW_ABI;
    m->exit_code=(uint32_t)m->r[0];m->exited=1;return CW_OK;
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
    if(p.tls_present){
        /* A single image and initial thread: isolated TEB, TLS vector and
           <=4 KiB template inside the lower 8 KiB of the guest stack arena. */
        store64(m->stack+8,m->stack_base+CW_STACK);
        store64(m->stack+16,m->stack_base+CW_TLS_RESERVE);
        store64(m->stack+0x30,m->stack_base);
        store64(m->stack+0x58,m->stack_base+0x800);
        store64(m->stack+0x800,m->stack_base+0x1000);
        if(p.tls_bytes)memcpy(m->stack+0x1000,arena+p.tls_rva,p.tls_bytes);
        memset(arena+p.tls_index,0,4);
    }
    /* Synthetic trusted caller: return token is not mapped or executable.
       Only a top-level RET with balanced stack can finish the environment. */
    bootstrap(m);
    return CW_OK;
}
