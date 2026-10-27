/* SPDX-License-Identifier: AGPL-3.0-only */
/* Bounded integer AMD64 interpreter. Unsupported encodings fail closed. */
#include "process.h"
#define CF 1U
#define PF 4U
#define AF 16U
#define ZF 64U
#define SF 128U
#define OF 2048U
typedef struct Cpu {
    uint64_t r[16], ip, cur, flags;
    unsigned int rex, rex_present, size;
    int fault;
    RyzLinuxMemory *m;
    RyzLinuxProcess *p;
    RyzVmResult *result;
} Cpu;
typedef struct Operand {
    int reg, high, rip;
    uint64_t address;
} Operand;
static uint64_t mask(unsigned int size)
{
    return size==8 ? UINT64_MAX : (UINT64_C(1)<<(size*8))-1;
}
static uint64_t load(Cpu *c,uint64_t at,unsigned int size,unsigned int flags)
{
    uint64_t v=0;
    unsigned int i;
    if(!ryz_memory_access(c->m,at,size,flags)){ c->fault=1; return 0; }
    for(i=0;i<size;i++) v|=(uint64_t)c->m->bytes[(size_t)(at-c->m->base)+i]<<(i*8);
    return v;
}
static void store(Cpu *c,uint64_t at,unsigned int size,uint64_t v)
{
    unsigned int i;
    if(c->fault)return;
    if(!ryz_memory_access(c->m,at,size,RYZ_WRITE)){ c->fault=1; return; }
    for(i=0;i<size;i++) c->m->bytes[(size_t)(at-c->m->base)+i]=(unsigned char)(v>>(i*8));
}
static uint64_t fetch(Cpu *c,unsigned int n)
{
    uint64_t v=load(c,c->cur,n,RYZ_EXEC);
    c->cur+=n;
    if(c->cur-c->ip>15) c->fault=1;
    return v;
}
static Operand regop(Cpu *c,unsigned int index,unsigned int size)
{
    Operand o;
    memset(&o,0,sizeof(o)); o.reg=(int)index;
    if(size==1 && !c->rex_present && index>=4 && index<8){ o.reg-=4; o.high=1; }
    return o;
}
static Operand decode(Cpu *c,unsigned int *reg,unsigned int *group,unsigned int size)
{
    unsigned int b=(unsigned int)fetch(c,1), mod=b>>6, rm=b&7, sib, base, index, scale;
    Operand o;
    *group=(b>>3)&7;
    *reg=*group+((c->rex&4)?8:0);
    if(mod==3) return regop(c,rm+((c->rex&1)?8:0),size);
    memset(&o,0,sizeof(o)); o.reg=-1;
    if(rm==4){
        sib=(unsigned int)fetch(c,1); base=sib&7; index=(sib>>3)&7; scale=sib>>6;
        if(index!=4 || (c->rex&2)) o.address=c->r[index+((c->rex&2)?8:0)]<<scale;
        if(mod==0 && base==5) o.address+=(uint64_t)(int64_t)(int32_t)fetch(c,4);
        else o.address+=c->r[base+((c->rex&1)?8:0)];
    }else if(mod==0 && rm==5){ o.rip=1; o.address=(uint64_t)(int64_t)(int32_t)fetch(c,4); }
    else o.address=c->r[rm+((c->rex&1)?8:0)];
    if(mod==1) o.address+=(uint64_t)(int64_t)(int8_t)fetch(c,1);
    if(mod==2) o.address+=(uint64_t)(int64_t)(int32_t)fetch(c,4);
    return o;
}
static uint64_t address(Cpu *c,Operand o){ return o.address+(o.rip?c->cur:0); }
static uint64_t get(Cpu *c,Operand o,unsigned int size)
{
    if(o.reg>=0) return (c->r[o.reg]>>(o.high?8:0))&mask(size);
    return load(c,address(c,o),size,RYZ_READ);
}
static void put(Cpu *c,Operand o,unsigned int size,uint64_t v)
{
    uint64_t bits=mask(size);
    unsigned int shift=o.high?8:0;
    if(c->fault)return;
    if(o.reg<0) store(c,address(c,o),size,v);
    else if(size==4 || size==8) c->r[o.reg]=v&bits;
    else c->r[o.reg]=(c->r[o.reg]&~(bits<<shift))|((v&bits)<<shift);
}
static uint64_t resultflags(Cpu *c,uint64_t v,unsigned int size)
{
    unsigned int parity=0, i;
    v&=mask(size);
    c->flags&=~(uint64_t)(CF|PF|AF|ZF|SF|OF);
    if(v==0) c->flags|=ZF;
    if((v>>(size*8-1))&1) c->flags|=SF;
    for(i=0;i<8;i++) parity^=(unsigned int)((v>>i)&1);
    if(parity==0) c->flags|=PF;
    return v;
}
static uint64_t arithmetic(Cpu *c,unsigned int group,uint64_t a,uint64_t b,unsigned int size)
{
    uint64_t v, full, bits=mask(size), sign=UINT64_C(1)<<(size*8-1);
    int carry=0, overflow=0, adjust=0;
    a&=bits; b&=bits;
    if(group==0){
        full=a+b; v=full&bits;
        carry=size==8?v<a:full>bits;
        overflow=(~(a^b)&(a^v)&sign)!=0;
        adjust=((a^b^v)&16)!=0;
    }else if(group==5 || group==7){
        v=(a-b)&bits; carry=a<b;
        overflow=((a^b)&(a^v)&sign)!=0; adjust=((a^b^v)&16)!=0;
    }else if(group==1) v=a|b;
    else if(group==6) v=a^b;
    else v=a&b;
    v=resultflags(c,v,size);
    if(carry) c->flags|=CF;
    if(overflow) c->flags|=OF;
    if(adjust) c->flags|=AF;
    return v;
}
static int condition(Cpu *c,unsigned int n)
{
    int cf=(c->flags&CF)!=0, z=(c->flags&ZF)!=0, s=(c->flags&SF)!=0;
    int o=(c->flags&OF)!=0, p=(c->flags&PF)!=0;
    switch(n&15){
    case 0:return o; case 1:return !o; case 2:return cf; case 3:return !cf;
    case 4:return z; case 5:return !z; case 6:return cf||z; case 7:return !cf&&!z;
    case 8:return s; case 9:return !s; case 10:return p; case 11:return !p;
    case 12:return s!=o; case 13:return s==o; case 14:return z||s!=o; default:return !z&&s==o;
    }
}
static void push(Cpu *c,uint64_t v){ store(c,c->r[4]-8,8,v); if(!c->fault)c->r[4]-=8; }
static uint64_t pop(Cpu *c){ uint64_t v=load(c,c->r[4],8,RYZ_READ); if(!c->fault)c->r[4]+=8; return v; }
static int guest_syscall(Cpu *c)
{
    RyzLinuxRegs r;
    uint64_t nr=c->r[0];
    if(nr!=0 && nr!=1 && nr!=3 && nr!=9 && nr!=10 && nr!=11 && nr!=12 &&
       nr!=39 && nr!=60 && nr!=102 && nr!=104 && nr!=186 && nr!=231 && nr!=257)
        return RYZ_VM_SYSCALL_UNSUPPORTED;
    r.rax=nr; r.rdi=c->r[7]; r.rsi=c->r[6]; r.rdx=c->r[2];
    r.r10=c->r[10]; r.r8=c->r[8]; r.r9=c->r[9];
    c->r[1]=c->cur; c->r[11]=c->flags;
    c->r[0]=(uint64_t)ryz_linux_syscall(c->p,&r);
    c->result->syscall_count++;
    return RYZ_VM_OK;
}
static int step(Cpu *c)
{
    unsigned int op, op2=0, n, reg=0, group=0, size, type, count;
    uint64_t a,b,v=0,target=0,saved;
    int jump=0, rv;
    Operand rm, rr;
    c->cur=c->ip; c->rex=c->rex_present=0; c->size=4;
    op=(unsigned int)fetch(c,1);
    if(op==0x66){ c->size=2; op=(unsigned int)fetch(c,1); }
    if(op>=0x40 && op<=0x4f){ c->rex=op&15; c->rex_present=1; if(c->rex&8)c->size=8; op=(unsigned int)fetch(c,1); }
    if(c->fault) return RYZ_VM_MAP_ERROR;
    size=c->size;
    if(size==2 && ((op>=0x50 && op<=0x5f) || op==0x68 || op==0x6a ||
                   op==0xe8 || op==0xc3 || op==0xc9 || op==0x63))
        return RYZ_VM_OPCODE_UNSUPPORTED;
    if(op>=0x50 && op<=0x57) push(c,c->r[op-0x50+((c->rex&1)?8:0)]);
    else if(op>=0x58 && op<=0x5f){ v=pop(c); c->r[op-0x58+((c->rex&1)?8:0)]=v; }
    else if(op==0x68 || op==0x6a){ v=fetch(c,op==0x68?4:1); v=op==0x68?(uint64_t)(int64_t)(int32_t)v:(uint64_t)(int64_t)(int8_t)v; push(c,v); }
    else if(op>=0xb8 && op<=0xbf){ v=fetch(c,size); put(c,regop(c,op-0xb8+((c->rex&1)?8:0),size),size,v); }
    else if(op>=0xb0 && op<=0xb7){ v=fetch(c,1); put(c,regop(c,op-0xb0+((c->rex&1)?8:0),1),1,v); }
    else if(op==0x88 || op==0x89 || op==0x8a || op==0x8b || op==0x8d){
        if(op==0x88 || op==0x8a) size=1;
        rm=decode(c,&reg,&group,size); rr=regop(c,reg,size);
        if(op==0x8d){ if(rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED; v=address(c,rm); put(c,rr,size,v); }
        else if(op==0x88 || op==0x89){ v=get(c,rr,size); if(!c->fault)put(c,rm,size,v); }
        else { v=get(c,rm,size); if(!c->fault)put(c,rr,size,v); }
    }else if(op==0xc6 || op==0xc7){
        if(op==0xc6)size=1;
        rm=decode(c,&reg,&group,size); if(group!=0)return RYZ_VM_OPCODE_UNSUPPORTED;
        v=fetch(c,size==8?4:size); if(size==8)v=(uint64_t)(int64_t)(int32_t)v;
        if(!c->fault)put(c,rm,size,v);
    }else if(op==0x63){
        rm=decode(c,&reg,&group,4); v=get(c,rm,4);
        if(!c->fault)put(c,regop(c,reg,size),size,(uint64_t)(int64_t)(int32_t)v);
    }else if((op<=0x3b && ((op&7)<=3) && ((op>>3)==0 || (op>>3)==1 || (op>>3)>=4)) || op==0x84 || op==0x85){
        type=op==0x84 || op==0x85?8:op>>3;
        if((op&1)==0)size=1;
        rm=decode(c,&reg,&group,size); rr=regop(c,reg,size);
        if((op&2) && type!=8){ Operand tmp=rm; rm=rr; rr=tmp; }
        a=get(c,rm,size); b=get(c,rr,size);
        if(!c->fault){ v=arithmetic(c,type,a,b,size); if(type!=7 && type!=8)put(c,rm,size,v); }
    }else if(op==0x80 || op==0x81 || op==0x83){
        if(op==0x80)size=1;
        rm=decode(c,&reg,&group,size);
        if(group==2 || group==3)return RYZ_VM_OPCODE_UNSUPPORTED;
        b=fetch(c,op==0x83?1:(size==8?4:size));
        if(op==0x83)b=(uint64_t)(int64_t)(int8_t)b;
        else if(size==8)b=(uint64_t)(int64_t)(int32_t)b;
        a=get(c,rm,size);
        if(!c->fault){ v=arithmetic(c,group,a,b,size); if(group!=7)put(c,rm,size,v); }
    }else if(op==0x04 || op==0x05 || op==0x0c || op==0x0d || op==0x24 || op==0x25 ||
             op==0x2c || op==0x2d || op==0x34 || op==0x35 || op==0x3c || op==0x3d || op==0xa8 || op==0xa9){
        if((op&1)==0)size=1;
        type=(op==0xa8 || op==0xa9)?8:op>>3;
        b=fetch(c,size==8?4:size); if(size==8)b=(uint64_t)(int64_t)(int32_t)b;
        rr=regop(c,0,size); a=get(c,rr,size);
        if(!c->fault){ v=arithmetic(c,type,a,b,size); if(type!=7 && type!=8)put(c,rr,size,v); }
    }else if(op==0xc1 || op==0xd1 || op==0xd3){
        rm=decode(c,&reg,&group,size);
        if(group!=4 && group!=5 && group!=7)return RYZ_VM_OPCODE_UNSUPPORTED;
        count=op==0xc1?(unsigned int)fetch(c,1):(op==0xd1?1:(unsigned int)c->r[1]);
        count&=size==8?63:31; a=get(c,rm,size); n=size*8;
        if(count!=0 && !c->fault){
            saved=c->flags; b=(a>>(n-1))&1;
            if(group==4){ v=count>=n?0:a<<count; type=count>n?0:(unsigned int)((a>>(n-count))&1); }
            else { type=count>n?0:(unsigned int)((a>>(count-1))&1); v=count>=n?0:a>>count;
                if(group==7 && b) v|=count>=n?mask(size):mask(size)^(mask(size)>>count); }
            v=resultflags(c,v,size); if(type)c->flags|=CF;
            if(count==1 && ((group==4 && (((v>>(n-1))&1)!=type)) || (group==5 && b)))c->flags|=OF;
            (void)saved; put(c,rm,size,v);
        }
    }else if(op==0xff){
        rm=decode(c,&reg,&group,8);
        if(group<=1){ a=get(c,rm,size); saved=c->flags&CF; v=arithmetic(c,group==0?0:5,a,1,size); c->flags=(c->flags&~(uint64_t)CF)|saved; if(!c->fault)put(c,rm,size,v); }
        else if(group==2 || group==4){ if(size==2)return RYZ_VM_OPCODE_UNSUPPORTED; target=get(c,rm,8); if(group==2 && !c->fault)push(c,c->cur); jump=1; }
        else if(group==6){ if(size==2)return RYZ_VM_OPCODE_UNSUPPORTED; a=get(c,rm,8); if(!c->fault)push(c,a); }
        else return RYZ_VM_OPCODE_UNSUPPORTED;
    }else if(op==0xf6 || op==0xf7){
        if(op==0xf6)size=1;
        rm=decode(c,&reg,&group,size);
        if(group==0){ b=fetch(c,size==8?4:size); if(size==8)b=(uint64_t)(int64_t)(int32_t)b; a=get(c,rm,size); if(!c->fault)arithmetic(c,8,a,b,size); }
        else if(group==2 || group==3){ a=get(c,rm,size); if(!c->fault){ v=group==2?~a:arithmetic(c,5,0,a,size); put(c,rm,size,v); } }
        else return RYZ_VM_OPCODE_UNSUPPORTED;
    }else if(op==0xe8 || op==0xe9 || op==0xeb){
        v=fetch(c,op==0xeb?1:4); v=op==0xeb?(uint64_t)(int64_t)(int8_t)v:(uint64_t)(int64_t)(int32_t)v;
        target=c->cur+v; jump=1; if(op==0xe8 && !c->fault)push(c,c->cur);
    }else if(op>=0x70 && op<=0x7f){ v=(uint64_t)(int64_t)(int8_t)fetch(c,1); target=c->cur+v; jump=condition(c,op); }
    else if(op==0xc3){ target=pop(c); jump=1; }
    else if(op==0xc9){ c->r[4]=c->r[5]; c->r[5]=pop(c); }
    else if(op==0x98){ v=size==8?(uint64_t)(int64_t)(int32_t)c->r[0]:(size==4?(uint64_t)(int64_t)(int16_t)c->r[0]:(uint64_t)(int64_t)(int8_t)c->r[0]); put(c,regop(c,0,size),size,v); }
    else if(op==0x99){ put(c,regop(c,2,size),size,(c->r[0]>>(size*8-1))&1?mask(size):0); }
    else if(op==0x90){ }
    else if(op==0x0f){
        op2=(unsigned int)fetch(c,1);
        if(op2==5){ if(c->fault)return RYZ_VM_MAP_ERROR; rv=guest_syscall(c); if(rv!=RYZ_VM_OK)return rv; }
        else if(op2>=0x80 && op2<=0x8f){ v=(uint64_t)(int64_t)(int32_t)fetch(c,4); target=c->cur+v; jump=condition(c,op2); }
        else if(op2==0xb6 || op2==0xb7 || op2==0xbe || op2==0xbf){
            n=(op2&1)?2:1; rm=decode(c,&reg,&group,n); v=get(c,rm,n);
            if(op2==0xbe)v=(uint64_t)(int64_t)(int8_t)v;
            if(op2==0xbf)v=(uint64_t)(int64_t)(int16_t)v;
            if(!c->fault)put(c,regop(c,reg,size),size,v);
        }else if(op2>=0x90 && op2<=0x9f){ rm=decode(c,&reg,&group,1); if(!c->fault)put(c,rm,1,(uint64_t)condition(c,op2)); }
        else if(op2>=0x40 && op2<=0x4f){ rm=decode(c,&reg,&group,size); v=get(c,rm,size); if(!c->fault){ if(condition(c,op2))put(c,regop(c,reg,size),size,v); else if(size==4)c->r[reg]&=mask(4); } }
        else if(op2==0x1f){ rm=decode(c,&reg,&group,size); (void)rm; if(group!=0)return RYZ_VM_OPCODE_UNSUPPORTED; }
        else return RYZ_VM_OPCODE_UNSUPPORTED;
    }else return RYZ_VM_OPCODE_UNSUPPORTED;
    if(c->fault) return RYZ_VM_MAP_ERROR;
    c->ip=jump?target:c->cur;
    return RYZ_VM_OK;
}
int ryz_cpu_run(RyzLinuxProcess *p,RyzLinuxMemory *m,uint64_t entry,uint64_t stack,RyzVmResult *result)
{
    Cpu c;
    uint32_t i;
    int rv;
    memset(&c,0,sizeof(c)); c.p=p; c.m=m; c.ip=entry; c.r[4]=stack; c.flags=0x202; c.result=result;
    for(i=0;i<RYZ_PROCESS_STEPS;i++){
        result->last_rip=c.ip; result->executed_steps=i+1;
        rv=step(&c);
        if(rv!=RYZ_VM_OK)return rv;
        if(p->exited){ result->exited=1; result->exit_status=p->exit_status; return RYZ_VM_OK; }
    }
    return RYZ_VM_STEP_LIMIT;
}
