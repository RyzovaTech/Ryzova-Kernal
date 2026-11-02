/* SPDX-License-Identifier: AGPL-3.0-only */
/* Strict, original, bounded ARM64-classic PE32+ interpreter research gate.
 * Not a native ARM64 Ryzova kernel, not a generic Windows binary launcher.
 * Only a small, import-free C compiler fixture instruction subset executes.
 * No host calls, no Win32 imports, no dynamic loading or guest I/O. */
#include "arm64_probe.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CW_A64_FILE_LIMIT (4U*1024U*1024U)
#define CW_A64_IMAGE_LIMIT (8U*1024U*1024U)
#define CW_A64_STACK (64U*1024U)
#define CW_A64_STEPS 4096U
#define CW_A64_SECTIONS 8U
#define CW_A64_R 0x40000000U
#define CW_A64_W 0x80000000U
#define CW_A64_X 0x20000000U
#define CW_A64_EXIT UINT64_C(0xffffffffffffffff)

typedef struct {
    uint32_t rva, mapped, raw_bytes, raw, flags;
} Section;
typedef struct {
    unsigned char *bytes;
    uint32_t image_bytes;
    Section sections[CW_A64_SECTIONS];
    unsigned int count;
    uint64_t x[31], sp;
    uint32_t pc;
    CwArm64Result *result;
} Machine;

static uint16_t read16(const unsigned char *p) {
    return (uint16_t)((unsigned int)p[0] | ((unsigned int)p[1]<<8));
}
static uint32_t read32(const unsigned char *p) {
    return (uint32_t)read16(p) | ((uint32_t)read16(p+2)<<16);
}
static uint64_t read64(const unsigned char *p) {
    return (uint64_t)read32(p) | ((uint64_t)read32(p+4)<<32);
}
static int within(size_t n,size_t pos,size_t length) {
    return pos<=n && length<=n-pos;
}
static int power2(uint32_t n) {
    return n && !(n&(n-1U));
}
static uint32_t round_page(uint32_t n) {
    return (n+4095U)&~4095U;
}
static int range(const Machine *m,uint64_t addr,unsigned int bytes,unsigned int flags) {
    unsigned int i;
    if(!bytes || addr>UINT32_MAX || bytes>UINT32_MAX-addr)return 0;
    if(addr>=m->image_bytes &&
       (uint64_t)addr+bytes<=(uint64_t)m->image_bytes+CW_A64_STACK)
        return !(flags&CW_A64_X);
    for(i=0;i<m->count;i++) {
        const Section *s=&m->sections[i];
        if(addr>=s->rva && addr-s->rva<s->mapped &&
           bytes<=s->mapped-(uint32_t)(addr-s->rva))
            return (s->flags&flags)==flags;
    }
    return 0;
}
static uint64_t getreg(const Machine *m,unsigned int i,int stack) {
    return i==31U?(stack?m->sp:0):m->x[i];
}
static void setreg(Machine *m,unsigned int i,uint64_t value,int wide,int stack) {
    if(!wide)value=(uint32_t)value;
    if(i==31U){if(stack)m->sp=value;}
    else m->x[i]=value;
}
static int exec_instruction(Machine *m) {
    const uint32_t word=read32(m->bytes+m->pc), rd=word&31U;
    const unsigned int rn=(word>>5)&31U;
    const uint32_t next=m->pc+4;
    CwArm64Result *r=m->result;
    uint32_t op=word&0x7f800000U;
    uint64_t value;
    r->last_rva=m->pc;
    r->last_opcode=word;
    if(word==0xd503201fU){m->pc=next;return -1;} /* NOP */
    if(op==0x52800000U || op==0x72800000U) {
        /* MOVZ / MOVK: 32-bit or 64-bit, logical zero register. */
        unsigned int shift=((word>>21)&3U)*16U;
        int wide=(word>>31)!=0;
        uint64_t imm=(uint64_t)((word>>5)&65535U)<<shift;
        if(!wide && shift>16U)return CW_A64_UNSUPPORTED;
        if(op==0x72800000U){
            uint64_t mask=UINT64_C(0xffff)<<shift;
            imm=(getreg(m,rd,0)&~mask)|imm;
        }
        setreg(m,rd,imm,wide,0);m->pc=next;return -1;
    }
    if((word&0x1f000000U)==0x11000000U && !(word&0x20000000U)) {
        /* ADD / SUB immediate, with special stack-pointer encoding. */
        unsigned int shift=(word>>22)&3U;
        uint64_t n=((word>>10)&4095U);
        int wide=(word>>31)!=0,subtract=!!(word&0x40000000U);
        if(shift>1U)return CW_A64_UNSUPPORTED;
        n<<=(shift*12U);
        if((rn==31U || rd==31U) && !wide)return CW_A64_UNSUPPORTED;
        value=getreg(m,rn,1);
        value=subtract?value-n:value+n;
        if(rd==31U){
            if(value<(uint64_t)m->image_bytes+16U ||
               value>(uint64_t)m->image_bytes+CW_A64_STACK ||
               (value&15U))return CW_A64_BAD_MEMORY;
        }
        setreg(m,rd,value,wide,1);m->pc=next;return -1;
    }
    if((word&0xffc00000U)==0xb9000000U ||
       (word&0xffc00000U)==0xb9400000U ||
       (word&0xffc00000U)==0xf9000000U ||
       (word&0xffc00000U)==0xf9400000U) {
        /* LDR/STR unsigned offset Wt/Xt (load-store grant checks). */
        int wide=(word>>30)!=0,isload=!!(word&0x00400000U);
        unsigned int bytes=wide?8U:4U,rt=rd;
        uint64_t addr=getreg(m,rn,1)+(((word>>10)&4095U)*bytes);
        if(!range(m,addr,bytes,isload?CW_A64_R:CW_A64_W))
            return CW_A64_BAD_MEMORY;
        if(isload) {
            value=wide?read64(m->bytes+(size_t)addr):
                       read32(m->bytes+(size_t)addr);
            setreg(m,rt,value,wide,0);
        }else {
            unsigned int i;
            value=getreg(m,rt,0);
            for(i=0;i<bytes;i++)m->bytes[(size_t)addr+i]=(unsigned char)(value>>(8U*i));
        }
        m->pc=next;return -1;
    }
    if((word&0xfffffc1fU)==0xd65f0000U) {
        /* RET Xn. Sentinel LR is a private launch return, not host code. */
        uint64_t target=getreg(m,rn,0);
        if(target==CW_A64_EXIT) {
            r->exit_code=(uint32_t)m->x[0];
            return CW_A64_OK;
        }
        if(target>UINT32_MAX || (target&3U) ||
           !range(m,target,4,CW_A64_X))return CW_A64_BAD_MEMORY;
        m->pc=(uint32_t)target;return -1;
    }
    if((word&0x7c000000U)==0x14000000U) {
        /* B / BL signed 26-bit PC-relative word displacement. */
        int64_t displacement=(int64_t)((int32_t)(word<<6)>>6)*4;
        int64_t target=(int64_t)m->pc+displacement;
        if(target<0 || target>UINT32_MAX || (target&3) ||
           !range(m,(uint64_t)target,4,CW_A64_X))
            return CW_A64_BAD_MEMORY;
        if(word&0x80000000U)m->x[30]=next;
        m->pc=(uint32_t)target;return -1;
    }
    /* SVC, system registers, arbitrary imports and unimplemented ISA
     * must fail closed. There is never a host NT or Linux syscall path. */
    return CW_A64_UNSUPPORTED;
}
int cw_arm64_pe_execute(const unsigned char *file,size_t length,
                        CwArm64Result *result) {
    uint32_t pe,op,sections_at,image_size,headers,entry,n_dirs,raw_start;
    uint32_t section_align,file_align,characteristics,virtual_size;
    unsigned int i,j,section_count;
    uint16_t opt_size;
    Machine m;int answer=CW_A64_BAD_PE;
    if(!result)return CW_A64_BAD_PE;
    memset(result,0,sizeof(*result));result->status=CW_A64_BAD_PE;
    if(!file || length<256U || length>CW_A64_FILE_LIMIT ||
       read16(file)!=0x5a4dU)return result->status;
    pe=read32(file+0x3c);
    if(!within(length,pe,24U) || memcmp(file+pe,"PE\0\0",4))return result->status;
    if(read16(file+pe+4)!=0xaa64U)return result->status;
    section_count=read16(file+pe+6);
    opt_size=read16(file+pe+20);
    characteristics=read16(file+pe+22);
    if(section_count<1U || section_count>CW_A64_SECTIONS ||
       !(characteristics&2U) || (characteristics&0x2000U) ||
       (characteristics&0x0100U) || opt_size<112U)
        return result->status;
    op=pe+24U;
    if(!within(length,op,opt_size))return result->status;
    if(read16(file+op)!=0x20bU || read16(file+op+68)!=3U)
        return result->status;
    section_align=read32(file+op+32);
    file_align=read32(file+op+36);
    image_size=read32(file+op+56);
    headers=read32(file+op+60);
    entry=read32(file+op+16);
    n_dirs=read32(file+op+108);
    if((section_align!=4096U && section_align!=65536U) ||
       !power2(file_align) || file_align<512U || file_align>4096U ||
       image_size<4096U || image_size>CW_A64_IMAGE_LIMIT ||
       (image_size&(section_align-1U)) || !headers ||
       headers>image_size || headers>length ||
       (headers&(file_align-1U)) || !entry || (entry&3U) ||
       !within(image_size,entry,4U) ||
       (read64(file+op+24)&65535U) || n_dirs>16U ||
       (uint64_t)112U+(uint64_t)n_dirs*8U>opt_size)
       return result->status;
    /* Only PE exception unwind directory is admitted, not imports,
     * base relocation, TLS, CLR, debug or hidden dynamic loaders. */
    for(i=0;i<n_dirs;i++)
        if(i!=3U && (read32(file+op+112+i*8U) ||
                     read32(file+op+116+i*8U)))
            return result->status;
    sections_at=op+opt_size;
    if(!within(length,sections_at,section_count*40U) ||
       !within(headers,sections_at,section_count*40U))
        return result->status;
    memset(&m,0,sizeof(m));
    m.count=section_count;m.image_bytes=image_size;m.result=result;
    for(i=0;i<section_count;i++) {
        size_t off=(size_t)sections_at+i*40U;
        Section *s=&m.sections[i];
        uint32_t raw_bytes=read32(file+off+16);
        raw_start=read32(file+off+20);
        virtual_size=read32(file+off+8);
        s->rva=read32(file+off+12);s->flags=read32(file+off+36);
        if(!virtual_size || !s->rva || (s->rva&(section_align-1U)) ||
           raw_bytes>UINT32_MAX-virtual_size ||
           (!raw_bytes && raw_start) ||
           (raw_bytes && (raw_start<headers || (raw_start&(file_align-1U)) ||
                          !within(length,raw_start,raw_bytes))) ||
           (s->flags&CW_A64_W && s->flags&CW_A64_X))
            return result->status;
        s->mapped=round_page(virtual_size>raw_bytes?virtual_size:raw_bytes);
        s->raw_bytes=raw_bytes;s->raw=raw_start;
        if(!s->mapped || !within(image_size,s->rva,s->mapped))
            return result->status;
        for(j=0;j<i;j++) {
            const Section *other=&m.sections[j];
            if(s->rva<other->rva+other->mapped &&
               other->rva<s->rva+s->mapped)return result->status;
            if(raw_bytes && other->raw_bytes &&
               raw_start<other->raw+other->raw_bytes &&
               other->raw<raw_start+raw_bytes)return result->status;
        }
    }
    /* PE exception directory must remain file-backed in a declared
     * section. It cannot authorize execution or untrusted imports. */
    if(n_dirs>3U && (read32(file+op+136U)||read32(file+op+140U))) {
        uint32_t rva=read32(file+op+136U),n=read32(file+op+140U);
        int found=0;
        if(!rva || !n || n%8U)return result->status;
        for(i=0;i<section_count;i++) {
            const Section *s=&m.sections[i];
            if(rva>=s->rva && within(s->raw_bytes,rva-s->rva,n) &&
               !(s->flags&CW_A64_X))found=1;
        }
        if(!found)return result->status;
    }
    {
        int found=0;
        for(i=0;i<section_count;i++) {
            const Section *s=&m.sections[i];
            if(entry>=s->rva && within(s->raw_bytes,entry-s->rva,4U) &&
               (s->flags&CW_A64_X) && !(s->flags&CW_A64_W))found=1;
        }
        if(!found)return result->status;
    }
    if(image_size>UINT32_MAX-CW_A64_STACK)return result->status;
    m.bytes=calloc(1,(size_t)image_size+CW_A64_STACK);
    if(!m.bytes){result->status=CW_A64_BAD_MEMORY;return result->status;}
    for(i=0;i<section_count;i++) {
        const Section *s=&m.sections[i];
        if(s->raw_bytes)memcpy(m.bytes+s->rva,file+s->raw,s->raw_bytes);
    }
    m.sp=(uint64_t)image_size+CW_A64_STACK;
    m.x[30]=CW_A64_EXIT;
    m.pc=entry;
    for(i=0;i<CW_A64_STEPS;i++) {
        if(!range(&m,m.pc,4U,CW_A64_X)) {
            answer=CW_A64_BAD_MEMORY;break;
        }
        result->executed_steps=i+1U;
        answer=exec_instruction(&m);
        if(answer>=0)break;
    }
    if(answer<0)answer=CW_A64_STEP_LIMIT;
    free(m.bytes);
    result->status=(unsigned int)answer;
    return answer;
}
