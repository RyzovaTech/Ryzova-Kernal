/* SPDX-License-Identifier: AGPL-3.0-only */
/* Windows-owned bounded AMD64 subset. No Linux process, host CPU jump or syscall. */
#include "api.h"
#include "files.h"
#ifndef CW_PLAN9
#include <string.h>
#endif
#define CF 1U
#define PF 4U
#define ZF 64U
#define SF 128U
#define OF 2048U
typedef struct Decode { CwMachine *m; uint64_t start,cur; unsigned int rex,prefix; int error; } Decode;
typedef struct Operand { int reg,high,rip;uint64_t at; } Operand;
static uint64_t mask(unsigned int n) { return n==8?UINT64_MAX:(UINT64_C(1)<<(8*n))-1; }
static uint64_t guest_read(Decode *d,uint64_t at,unsigned int n,unsigned int rights) {
    unsigned char b[8];unsigned int i;uint64_t v=0;
    if(d->error)return 0;
    if(cw_read(d->m,at,b,n,rights)){d->error=CW_MEMORY;return 0;}
    for(i=0;i<n;i++)v|=(uint64_t)b[i]<<(8*i);
    return v;
}
static void writen(Decode *d,uint64_t at,unsigned int n,uint64_t v) {
    unsigned char b[8];unsigned int i;
    if(d->error)return;
    for(i=0;i<n;i++)b[i]=(unsigned char)(v>>(8*i));
    if(cw_write(d->m,at,b,n))d->error=CW_MEMORY;
}
static uint64_t fetch(Decode *d,unsigned int n) {
    uint64_t v;
    if(d->cur-d->start+n>15){d->error=CW_OPCODE;return 0;}
    v=guest_read(d,d->cur,n,CW_X);d->cur+=n;return v;
}
static Operand regop(Decode *d,unsigned int reg,unsigned int n) {
    Operand o;memset(&o,0,sizeof(o));o.reg=(int)reg;
    if(n==1 && !d->rex && reg>=4 && reg<8){o.reg-=4;o.high=1;}
    return o;
}
static Operand operand(Decode *d,unsigned int *reg,unsigned int *group,unsigned int n) {
    unsigned int b=(unsigned int)fetch(d,1),mod=b>>6,rm=b&7,sib,base,index;
    Operand o;memset(&o,0,sizeof(o));o.reg=-1;
    *group=(b>>3)&7;*reg=*group+((d->rex&4)?8:0);
    if(mod==3)return regop(d,rm+((d->rex&1)?8:0),n);
    if(rm==4) {
        sib=(unsigned int)fetch(d,1);base=sib&7;index=(sib>>3)&7;
        if(index!=4 || (d->rex&2))o.at=d->m->r[index+((d->rex&2)?8:0)]<<(sib>>6);
        if(mod==0 && base==5)o.at+=(uint64_t)(int64_t)(int32_t)fetch(d,4);
        else o.at+=d->m->r[base+((d->rex&1)?8:0)];
    }else if(mod==0 && rm==5){o.rip=1;o.at=(uint64_t)(int64_t)(int32_t)fetch(d,4);}
    else o.at=d->m->r[rm+((d->rex&1)?8:0)];
    if(mod==1)o.at+=(uint64_t)(int64_t)(int8_t)fetch(d,1);
    if(mod==2)o.at+=(uint64_t)(int64_t)(int32_t)fetch(d,4);
    return o;
}
static uint64_t address(Decode *d,Operand o) { return o.at+(o.rip?d->cur:0); }
static uint64_t get(Decode *d,Operand o,unsigned int n) {
    if(o.reg>=0)return (d->m->r[o.reg]>>(o.high?8:0))&mask(n);
    return guest_read(d,address(d,o),n,CW_R);
}
static void put(Decode *d,Operand o,unsigned int n,uint64_t v) {
    unsigned int shift=o.high?8:0;uint64_t bits=mask(n);
    if(d->error)return;
    if(o.reg<0)writen(d,address(d,o),n,v);
    else if(n>=4)d->m->r[o.reg]=v&bits;
    else d->m->r[o.reg]=(d->m->r[o.reg]&~(bits<<shift))|((v&bits)<<shift);
}
static void result_flags(Decode *d,uint64_t v,unsigned int n) {
    unsigned int i,parity=0;uint64_t sign=UINT64_C(1)<<(8*n-1);
    v&=mask(n);for(i=0;i<8;i++)parity^=(unsigned int)((v>>i)&1);
    d->m->flags&=~(uint64_t)(ZF|SF|PF);
    d->m->flags|=(!v?ZF:0)|((v&sign)?SF:0)|(!parity?PF:0);
}
static uint64_t alu(Decode *d,unsigned int op,uint64_t a,uint64_t b,unsigned int n) {
    uint64_t bits=mask(n),sign=UINT64_C(1)<<(8*n-1),v=0;
    a&=bits;b&=bits;
    d->m->flags&=~(uint64_t)(CF|OF|16U);
    switch(op) {
    case 0:v=(a+b)&bits;if(v<a)d->m->flags|=CF;if((~(a^b)&(a^v)&sign))d->m->flags|=OF;break;
    case 1:v=a|b;break;
    case 4:v=a&b;break;
    case 5:case 7:v=(a-b)&bits;if(a<b)d->m->flags|=CF;if(((a^b)&(a^v)&sign))d->m->flags|=OF;break;
    case 6:v=a^b;break;
    default:d->error=CW_OPCODE;return 0;
    }
    if((op==0 || op==5 || op==7) && ((a^b^v)&16))d->m->flags|=16;
    result_flags(d,v,n);return v;
}
static int condition(CwMachine *m,unsigned int n) {
    int c=!!(m->flags&CF),z=!!(m->flags&ZF),s=!!(m->flags&SF),o=!!(m->flags&OF),p=!!(m->flags&PF),v;
    switch(n>>1){case 0:v=o;break;case 1:v=c;break;case 2:v=z;break;case 3:v=c||z;break;case 4:v=s;break;case 5:v=p;break;case 6:v=s!=o;break;default:v=z||(s!=o);break;}
    return (n&1)?!v:v;
}
static void push(Decode *d,uint64_t v) {
    uint64_t sp=d->m->r[4]-8;writen(d,sp,8,v);if(!d->error)d->m->r[4]=sp;
}
static uint64_t pop(Decode *d) {
    uint64_t v=guest_read(d,d->m->r[4],8,CW_R);if(!d->error)d->m->r[4]+=8;return v;
}
static void vector(Decode *d,Operand o,unsigned int reg,int to_operand) {
    unsigned char bytes[16];uint64_t at=address(d,o);
    if(to_operand){memcpy(bytes,d->m->xmm[reg],16);if(o.reg>=0)memcpy(d->m->xmm[o.reg],bytes,16);else if(cw_write(d->m,at,bytes,16))d->error=CW_MEMORY;}
    else {if(o.reg>=0)memcpy(bytes,d->m->xmm[o.reg],16);else if(cw_read(d->m,at,bytes,16,CW_R)){d->error=CW_MEMORY;return;}memcpy(d->m->xmm[reg],bytes,16);}
}
static uint64_t sign_extend(uint64_t value,unsigned int bytes) {
    uint64_t bits=mask(bytes);return (value&(UINT64_C(1)<<(bytes*8-1)))?value|~bits:value&bits;
}
static void product(uint64_t a,uint64_t b,unsigned int n,int signed_product,uint64_t *low,uint64_t *high) {
    uint64_t bits=mask(n),lo,hi;
    a&=bits;b&=bits;
    if(n<8){uint64_t full=a*b;lo=full&bits;hi=(full>>(8*n))&bits;}
    else {
        uint64_t a0=(uint32_t)a,a1=a>>32,b0=(uint32_t)b,b1=b>>32;
        uint64_t w0=a0*b0,t=a1*b0+(w0>>32),w1=t&UINT32_MAX,w2=t>>32;
        w1+=a0*b1;hi=a1*b1+w2+(w1>>32);lo=(w1<<32)|(w0&UINT32_MAX);
    }
    if(signed_product){uint64_t sign=UINT64_C(1)<<(8*n-1);hi=(hi-((a&sign)?b:0)-((b&sign)?a:0))&bits;}
    *low=lo;*high=hi;
}
static void multiply_flags(Decode *d,uint64_t lo,uint64_t hi,unsigned int n,int is_signed) {
    uint64_t expected=is_signed && (lo&(UINT64_C(1)<<(8*n-1)))?mask(n):0;
    d->m->flags&=~(uint64_t)(CF|OF);if(hi!=expected)d->m->flags|=CF|OF;
}
static int divide_pair(uint64_t hi,uint64_t lo,uint64_t divisor,unsigned int n,uint64_t *quotient,uint64_t *remainder) {
    unsigned int i=n*8;uint64_t q=0,r=hi;
    if(!divisor || hi>=divisor)return CW_DIVIDE;
    while(i--) {
        uint64_t carry=r>>63;r=(r<<1)|((lo>>i)&1);
        if(carry || r>=divisor){r-=divisor;q|=UINT64_C(1)<<i;}
    }
    *quotient=q;*remainder=r;return CW_OK;
}
static void guest_muldiv(Decode *d,unsigned int group,uint64_t operand_value,unsigned int n) {
    uint64_t lo,hi,a=d->m->r[0]&mask(n),b=operand_value&mask(n),bits=mask(n),sign=UINT64_C(1)<<(8*n-1),q,r;
    if(group==4 || group==5) {
        product(a,b,n,group==5,&lo,&hi);multiply_flags(d,lo,hi,n,group==5);
    }else {
        int negative_dividend,negative_divisor;
        lo=a;hi=n==1?(d->m->r[0]>>8)&255:d->m->r[2]&bits;
        negative_dividend=group==7 && !!(hi&sign);negative_divisor=group==7 && !!(b&sign);
        if(negative_dividend){lo=(~lo+1)&bits;hi=(~hi+(lo==0))&bits;}
        if(negative_divisor)b=(~b+1)&bits;
        if(divide_pair(hi,lo,b,n,&q,&r)){d->error=CW_DIVIDE;return;}
        if(group==7) {
            int negative_quotient=negative_dividend!=negative_divisor;
            if(q>(negative_quotient?sign:sign-1)){d->error=CW_DIVIDE;return;}
            if(negative_quotient)q=(~q+1)&bits;
            if(negative_dividend)r=(~r+1)&bits;
        }
        lo=q;hi=r;
    }
    if(n==1)put(d,regop(d,0,2),2,lo|(hi<<8));
    else {put(d,regop(d,0,n),n,lo);put(d,regop(d,2,n),n,hi);}
}
static uint64_t shift(Decode *d,unsigned int group,uint64_t value,unsigned int n,unsigned int count) {
    uint64_t v=value&mask(n),sign=UINT64_C(1)<<(n*8-1),carry=0;unsigned int i;
    count&=n==8?63U:31U;
    if(group==0 || group==1)count%=n*8;
    if(!count)return v;
    for(i=0;i<count;i++) {
        if(group==0){carry=!!(v&sign);v=((v<<1)|carry)&mask(n);}
        else if(group==1){carry=v&1;v=(v>>1)|(carry?sign:0);}
        else if(group==4 || group==6){carry=!!(v&sign);v=(v<<1)&mask(n);}
        else if(group==5){carry=v&1;v>>=1;}
        else if(group==7){carry=v&1;v=(v>>1)|(v&sign);}
        else {d->error=CW_OPCODE;return 0;}
    }
    d->m->flags=(d->m->flags&~(uint64_t)CF)|(carry?CF:0);
    if(group>=4)result_flags(d,v,n);
    if(count==1) {
        int overflow=(group==0 || group==4 || group==6)?(!!(v&sign)!=(int)carry):
            group==1?(!!(v&sign)!=!!(v&(sign>>1))):group==5?!!(value&sign):0;
        d->m->flags=(d->m->flags&~(uint64_t)OF)|(overflow?OF:0);
    }
    return v;
}
static int tick(CwMachine *m) {
    Decode d;Operand o,q;unsigned int op,n,reg=0,group=0,prefixes=0;
    uint64_t a,b,v,target=0;int jump=0;
    memset(&d,0,sizeof(d));d.m=m;d.start=d.cur=m->ip;
    op=(unsigned int)fetch(&d,1);
    while((op>=0x40 && op<=0x4f) || op==0x66 || op==0xf3 || op==0xf2) {
        if(++prefixes>2){d.error=CW_OPCODE;break;}
        if(op>=0x40 && op<=0x4f){if(d.rex){d.error=CW_OPCODE;break;}d.rex=op;}
        else {if(d.prefix || d.rex){d.error=CW_OPCODE;break;}d.prefix=op;}
        op=(unsigned int)fetch(&d,1);
    }
    n=(d.rex&8)?8:(d.prefix==0x66?2:4);
    if(d.error)return d.error;
    if((d.prefix==0xf3 || d.prefix==0xf2) && op!=0x0f)return CW_OPCODE;
    if(op>=0xb8 && op<=0xbf){v=fetch(&d,n);put(&d,regop(&d,(op-0xb8)+((d.rex&1)?8:0),n),n,v);}
    else if(op>=0xb0 && op<=0xb7){v=fetch(&d,1);put(&d,regop(&d,(op-0xb0)+((d.rex&1)?8:0),1),1,v);}
    else if(op>=0x50 && op<=0x57){if(d.prefix)return CW_OPCODE;push(&d,m->r[(op-0x50)+((d.rex&1)?8:0)]);}
    else if(op>=0x58 && op<=0x5f){if(d.prefix)return CW_OPCODE;v=pop(&d);if(!d.error)m->r[(op-0x58)+((d.rex&1)?8:0)]=v;}
    else if(op==0x68 || op==0x6a){if(d.prefix)return CW_OPCODE;v=op==0x68?(uint64_t)(int64_t)(int32_t)fetch(&d,4):(uint64_t)(int64_t)(int8_t)fetch(&d,1);push(&d,v);}
    else if(op==0x90){if(d.rex || d.prefix)return CW_OPCODE;}
    else if(op==0xc3){
        if(d.rex || d.prefix)return CW_OPCODE;
        a=m->r[4];v=pop(&d);
        if(!d.error && v==UINT64_MAX) {
            if(a!=m->initial_sp)return CW_ABI;
            m->exit_code=(uint32_t)m->r[0];m->exited=1;
        }else {jump=1;target=v;}
    }
    else if(op==0xc9){if(d.prefix || d.rex)return CW_OPCODE;m->r[4]=m->r[5];v=pop(&d);if(!d.error)m->r[5]=v;}
    else if(op==0xe8 || op==0xe9 || op==0xeb){if(d.prefix || d.rex)return CW_OPCODE;b=op==0xeb?(uint64_t)(int64_t)(int8_t)fetch(&d,1):(uint64_t)(int64_t)(int32_t)fetch(&d,4);target=d.cur+b;jump=1;if(op==0xe8)push(&d,d.cur);}
    else if(op>=0x70 && op<=0x7f){if(d.prefix || d.rex)return CW_OPCODE;b=(uint64_t)(int64_t)(int8_t)fetch(&d,1);if(condition(m,op&15)){jump=1;target=d.cur+b;}}
    else if(op==0x88 || op==0x89 || op==0x8a || op==0x8b || op==0x8d){
        if(op==0x88 || op==0x8a)n=1;
        o=operand(&d,&reg,&group,n);q=regop(&d,reg,n);
        if(op==0x8d){if(o.reg>=0)return CW_OPCODE;put(&d,q,n,address(&d,o));}
        else if(op==0x88 || op==0x89)put(&d,o,n,get(&d,q,n));
        else put(&d,q,n,get(&d,o,n));
    }
    else if(op==0xc6 || op==0xc7){if(op==0xc6)n=1;o=operand(&d,&reg,&group,n);if(group)return CW_OPCODE;v=fetch(&d,n==8?4:n);if(n==8)v=(uint64_t)(int64_t)(int32_t)v;put(&d,o,n,v);}
    else if(op<=0x3d && ((op&7)<=5)) {
        unsigned int kind=op>>3,form=op&7;
        if(kind==2 || kind==3)return CW_OPCODE; /* ADC/SBB not in W2. */
        if(!(form&1))n=1;
        if(form<=3){o=operand(&d,&reg,&group,n);q=regop(&d,reg,n);if(form&2){Operand tmp=o;o=q;q=tmp;}a=get(&d,o,n);b=get(&d,q,n);}
        else {o=regop(&d,0,n);b=fetch(&d,n==8?4:n);if(n==8)b=(uint64_t)(int64_t)(int32_t)b;a=get(&d,o,n);}
        v=alu(&d,kind,a,b,n);if(kind!=7)put(&d,o,n,v);
    }
    else if(op==0x80 || op==0x81 || op==0x83){if(op==0x80)n=1;o=operand(&d,&reg,&group,n);b=fetch(&d,op==0x83?1:(n==8?4:n));if(op==0x83)b=(uint64_t)(int64_t)(int8_t)b;else if(n==8)b=(uint64_t)(int64_t)(int32_t)b;a=get(&d,o,n);v=alu(&d,group,a,b,n);if(group!=7)put(&d,o,n,v);}
    else if(op==0x84 || op==0x85){if(op==0x84)n=1;o=operand(&d,&reg,&group,n);(void)alu(&d,4,get(&d,o,n),get(&d,regop(&d,reg,n),n),n);}
    else if(op==0x63){if(n==2)return CW_OPCODE;o=operand(&d,&reg,&group,4);put(&d,regop(&d,reg,n),n,sign_extend(get(&d,o,4),4));}
    else if(op==0x98){unsigned int small=n/2;put(&d,regop(&d,0,n),n,sign_extend(m->r[0]&mask(small),small));}
    else if(op==0x99){put(&d,regop(&d,2,n),n,(m->r[0]&(UINT64_C(1)<<(n*8-1)))?mask(n):0);}
    else if(op==0x69 || op==0x6b){uint64_t high;o=operand(&d,&reg,&group,n);b=fetch(&d,op==0x6b?1:(n==8?4:n));b=sign_extend(b,op==0x6b?1:(n==8?4:n));a=get(&d,o,n);product(a,b,n,1,&v,&high);multiply_flags(&d,v,high,n,1);put(&d,regop(&d,reg,n),n,v);}
    else if(op==0xf6 || op==0xf7){
        if(op==0xf6)n=1;
        o=operand(&d,&reg,&group,n);
        if(group==0){b=fetch(&d,n==8?4:n);if(n==8)b=sign_extend(b,4);(void)alu(&d,4,get(&d,o,n),b,n);}
        else if(group==2)put(&d,o,n,~get(&d,o,n));
        else if(group==3){v=alu(&d,5,0,get(&d,o,n),n);put(&d,o,n,v);}
        else if(group>=4){a=get(&d,o,n);if(!d.error)guest_muldiv(&d,group,a,n);}
        else return CW_OPCODE;
    }
    else if(op==0xc0 || op==0xc1 || (op>=0xd0 && op<=0xd3)){
        unsigned int count;if(op==0xc0 || op==0xd0 || op==0xd2)n=1;
        o=operand(&d,&reg,&group,n);
        count=(op==0xc0 || op==0xc1)?(unsigned int)fetch(&d,1):(op==0xd0 || op==0xd1)?1U:(unsigned int)(m->r[1]&255);
        if(group==2 || group==3)return CW_OPCODE;
        v=shift(&d,group,get(&d,o,n),n,count);put(&d,o,n,v);
    }
    else if(op==0xff){o=operand(&d,&reg,&group,n);if(group==2 || group==4 || group==6){if(d.prefix)return CW_OPCODE;v=get(&d,o,8);if(group==6)push(&d,v);else {if(group==2)push(&d,d.cur);jump=1;target=v;}}else if(group<2){a=m->flags&CF;v=alu(&d,group?5:0,get(&d,o,n),1,n);m->flags=(m->flags&~(uint64_t)CF)|a;put(&d,o,n,v);}else return CW_OPCODE;}
    else if(op==0x0f){
        unsigned int second=(unsigned int)fetch(&d,1);
        if((d.prefix==0xf3 && second!=0x6f && second!=0x7f) ||
            (d.prefix==0xf2 && second!=0x10 && second!=0x11))return CW_OPCODE;
        if(second>=0x80 && second<=0x8f){if(d.prefix || d.rex)return CW_OPCODE;b=(uint64_t)(int64_t)(int32_t)fetch(&d,4);if(condition(m,second&15)){jump=1;target=d.cur+b;}}
        else if(second==0xaf){uint64_t high;o=operand(&d,&reg,&group,n);product(get(&d,regop(&d,reg,n),n),get(&d,o,n),n,1,&v,&high);multiply_flags(&d,v,high,n,1);put(&d,regop(&d,reg,n),n,v);}
        else if(second==0xbe || second==0xbf){unsigned int small=second==0xbe?1:2;o=operand(&d,&reg,&group,small);put(&d,regop(&d,reg,n),n,sign_extend(get(&d,o,small),small));}
        else if(second==0xb6 || second==0xb7){unsigned int small=second==0xb6?1:2;o=operand(&d,&reg,&group,small);put(&d,regop(&d,reg,n),n,get(&d,o,small));}
        else if(second>=0x90 && second<=0x9f){o=operand(&d,&reg,&group,1);put(&d,o,1,(uint64_t)condition(m,second&15));}
        else if(second>=0x40 && second<=0x4f){o=operand(&d,&reg,&group,n);v=get(&d,o,n);if(condition(m,second&15))put(&d,regop(&d,reg,n),n,v);}
        else if((second==0x10 || second==0x11) && d.prefix==0xf2){
            /* Original SSE2 legacy MOVSD scalar *bit transport*, not FP
             * arithmetic. Intel F2 0F 10/11: reg source preserves high
             * destination quadword; m64 load clears destination high
             * quadword; m64 store writes exactly the low eight bytes.
             * Flags unchanged; all guest memory rights remain enforced. */
            unsigned char lane[8];
            o=operand(&d,&reg,&group,8);
            if(!d.error && second==0x10){
                if(o.reg>=0)memcpy(m->xmm[reg],m->xmm[o.reg],8);
                else if(cw_read(m,address(&d,o),lane,8,CW_R))d.error=CW_MEMORY;
                else {memcpy(m->xmm[reg],lane,8);memset(m->xmm[reg]+8,0,8);}
            }else if(!d.error){
                if(o.reg>=0)memcpy(m->xmm[o.reg],m->xmm[reg],8);
                else if(cw_write(m,address(&d,o),m->xmm[reg],8))d.error=CW_MEMORY;
            }
        }
        else if((second==0x6f || second==0x7f) && d.prefix==0xf3){o=operand(&d,&reg,&group,8);if(!d.error)vector(&d,o,reg,second==0x7f);}
        else if(second==0xef && d.prefix==0x66){unsigned int k;o=operand(&d,&reg,&group,8);if(o.reg<0)return CW_OPCODE;for(k=0;k<16;k++)m->xmm[reg][k]^=m->xmm[o.reg][k];}
        else if(second==0x1f){o=operand(&d,&reg,&group,n);if(group)return CW_OPCODE;}
        else return CW_OPCODE; /* SYSCALL/SYSENTER, privileged and unknown opcodes fail closed. */
    }
    else return CW_OPCODE;
    if(d.error)return d.error;
    m->ip=jump?target:d.cur;return CW_OK;
}
int cw_run(CwMachine *m,uint32_t budget) {
    if(!m || !m->image || !m->stack)return CW_HEADER;
    if(m->status)return m->status;
    if(m->exited)return CW_OK;
    if(!budget || budget>CW_MAX_STEPS){cw_files_close_all(m);return m->status=CW_BUDGET;}
    while(m->instructions<budget){int status;if(m->ip<CW_THUNK_BASE)m->last_guest_ip=m->ip;m->instructions++;status=m->ip>=CW_THUNK_BASE?cw_api_dispatch(m):tick(m);if(status){cw_files_close_all(m);return m->status=status;}if(m->exited){cw_files_close_all(m);return CW_OK;}}
    cw_files_close_all(m);return m->status=CW_BUDGET;
}

const char *cw_status_name(int status) {
    static const char *const names[]={"ok","bad-header","unsupported-image","bounds","unsafe-mapping","bad-relocation","memory-fault","unsupported-opcode","instruction-budget","abi-violation","api-policy","integer-divide-error","crt-contract"};
    return status>=0 && (unsigned int)status<sizeof(names)/sizeof(names[0])?names[status]:"unknown";
}
