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
typedef struct Decode { CwMachine *m; uint64_t start,cur; unsigned int rex,prefix,gs,addr32,locked; int error; } Decode;
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
static uint64_t address(Decode *d,Operand o) {
    uint64_t at=o.at+(o.rip?d->cur:0);
    if(d->addr32)at=(uint32_t)at;
    if(d->gs){
        if(!d->m->plan.tls_present || at>UINT64_MAX-d->m->stack_base){d->error=CW_MEMORY;return 0;}
        at+=d->m->stack_base;
    }
    return at;
}
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
    uint64_t bits=mask(n),sign=UINT64_C(1)<<(8*n-1),v=0,carry=!!(d->m->flags&CF),t;
    a&=bits;b&=bits;
    d->m->flags&=~(uint64_t)(CF|OF|16U);
    switch(op) {
    case 0:v=(a+b)&bits;if(v<a)d->m->flags|=CF;if((~(a^b)&(a^v)&sign))d->m->flags|=OF;break;
    case 1:v=a|b;break;
    case 2:t=(a+b)&bits;v=(t+carry)&bits;if(t<a || v<t)d->m->flags|=CF;if((~(a^b)&(a^v)&sign))d->m->flags|=OF;break;
    case 3:v=(a-b-carry)&bits;if(a<b || (carry && a==b))d->m->flags|=CF;if(((a^b)&(a^v)&sign))d->m->flags|=OF;break;
    case 4:v=a&b;break;
    case 5:case 7:v=(a-b)&bits;if(a<b)d->m->flags|=CF;if(((a^b)&(a^v)&sign))d->m->flags|=OF;break;
    case 6:v=a^b;break;
    default:d->error=CW_OPCODE;return 0;
    }
    if((op==0 || op==2 || op==3 || op==5 || op==7) && ((a^b^v)&16))d->m->flags|=16;
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
static uint64_t xmm_low(const unsigned char *p,unsigned int width) {
    uint64_t result=0;
    unsigned int i;
    for(i=0;i<width;i++)result|=(uint64_t)p[i]<<(i*8);
    return result;
}

static void xmm_put(unsigned char *p,unsigned int width,uint64_t value) {
    unsigned int i;
    for(i=0;i<width;i++)p[i]=(unsigned char)(value>>(i*8));
}

static int xmm_read(Decode *d,Operand o,unsigned char *out,unsigned int n) {
    uint64_t at;
    if(d->error)return d->error;
    if(o.reg>=0){memcpy(out,d->m->xmm[o.reg],n);return CW_OK;}
    at=address(d,o);
    if(d->error)return d->error;
    return cw_read(d->m,at,out,n,CW_R);
}

static int xmm_write(Decode *d,Operand o,const unsigned char *src,unsigned int n,int clear) {
    uint64_t at;
    if(d->error)return d->error;
    if(o.reg>=0){
        memmove(d->m->xmm[o.reg],src,n);
        if(clear)memset(d->m->xmm[o.reg]+n,0,16-n);
        return CW_OK;
    }
    at=address(d,o);
    if(d->error)return d->error;
    return cw_write(d->m,at,src,n);
}

#define FP_EXP UINT64_C(0x7ff0000000000000)
#define FP_FRAC UINT64_C(0x000fffffffffffff)
static int fp_nan(uint64_t bits) { return (bits&FP_EXP)==FP_EXP && (bits&FP_FRAC); }
static double double_value(uint64_t bits) { double d;memcpy(&d,&bits,8);return d; }
static uint64_t double_bits(double d) { uint64_t bits;memcpy(&bits,&d,8);return bits; }

static int packed_double(Decode *d,unsigned int op,unsigned int reg,Operand o) {
    unsigned char source[16], result[16]={0};
    unsigned int i,predicate=0;
    uint64_t a,b,value;
    double x,y;
    int status,unordered,less,equal,test;
    if(op==0xc2)predicate=(unsigned int)fetch(d,1)&7;
    status=xmm_read(d,o,source,d->prefix==0xf3?8:16);
    if(status)return status;
    for(i=0;i<2;i++){
        if(d->prefix==0xf3){
            xmm_put(result+8*i,8,double_bits((double)(int32_t)xmm_low(source+4*i,4)));
            continue;
        }
        b=xmm_low(source+8*i,8);
        if(op==0xe6){
            value=UINT32_C(0x80000000);
            y=double_value(b);
            if((b&FP_EXP)!=FP_EXP && y>=-2147483648.0 && y<2147483648.0){
                value=(uint32_t)(int32_t)y;
                if((double)(int32_t)value!=y)d->m->mxcsr|=32;
            }else{
                if(!(d->m->mxcsr&128))return CW_OPCODE;
                d->m->mxcsr|=1;
            }
            xmm_put(result+4*i,4,value);
            continue;
        }
        a=xmm_low(d->m->xmm[reg]+8*i,8);
        unordered=fp_nan(a)||fp_nan(b);
        less=equal=0;
        if(unordered){
            if(predicate==1 || predicate==2 || predicate==5 || predicate==6 ||
               (fp_nan(a) && !(a&UINT64_C(0x8000000000000))) ||
               (fp_nan(b) && !(b&UINT64_C(0x8000000000000)))){
                if(!(d->m->mxcsr&128))return CW_OPCODE;
                d->m->mxcsr|=1;
            }
        }else{
            x=double_value(a);y=double_value(b);less=x<y;equal=x==y;
        }
        test=predicate%4==0?equal:predicate%4==1?less:predicate%4==2?less||equal:unordered;
        if(predicate&4)test=!test;
        xmm_put(result+8*i,8,test?UINT64_MAX:0);
    }
    memcpy(d->m->xmm[reg],result,16);
    return CW_OK;
}

static int scalar_double(Decode *d,unsigned int op,unsigned int reg,Operand o,unsigned int width) {
    CwMachine *m=d->m;
    unsigned char source[8],*dst=m->xmm[reg];
    uint64_t a,b,value;
    double x,y,r,limit;
    int status,unordered,less,equal;
    if(op==0x10){
        status=xmm_read(d,o,source,8);
        if(status)return status;
        memcpy(dst,source,8);
        if(o.reg<0)memset(dst+8,0,8);
        return CW_OK;
    }
    if(op==0x11)return xmm_write(d,o,dst,8,0);
    if(op==0x2a){
        value=get(d,o,width);
        if(d->error)return d->error;
        if(m->mxcsr&0xe040U)return CW_OPCODE;
        r=width==8?(double)(int64_t)value:(double)(int32_t)value;
        xmm_put(dst,8,double_bits(r));
        return CW_OK;
    }
    status=xmm_read(d,o,source,8);
    if(status)return status;
    a=xmm_low(dst,8);b=xmm_low(source,8);
    if(op==0x2c){
        limit=width==8?9223372036854775808.0:2147483648.0;
        value=UINT64_C(1)<<(width*8-1);
        if((b&FP_EXP)!=FP_EXP){
            y=double_value(b);
            if(y>=-limit && y<limit){
                value=(uint64_t)(int64_t)y;
                if((double)(int64_t)value!=y)m->mxcsr|=32;
                put(d,regop(d,reg,width),width,value);
                return CW_OK;
            }
        }
        if(!(m->mxcsr&128))return CW_OPCODE;
        m->mxcsr|=1;
        put(d,regop(d,reg,width),width,value);
        return CW_OK;
    }
    unordered=fp_nan(a) || fp_nan(b);
    if(op==0x2e || op==0x2f){
        if(unordered){
            if(op==0x2f || (fp_nan(a) && !(a&UINT64_C(0x8000000000000))) ||
               (fp_nan(b) && !(b&UINT64_C(0x8000000000000)))){
                if(!(m->mxcsr&128))return CW_OPCODE;
                m->mxcsr|=1;
            }
            less=equal=1;
        }else {
            x=double_value(a);y=double_value(b);less=x<y;equal=x==y;
        }
        m->flags=(m->flags&~UINT64_C(0x8d5))|(less?CF:0)|(equal?ZF:0)|(unordered?PF:0);
        return CW_OK;
    }
    if(op==0x5d || op==0x5f){
        if(unordered){if(!(m->mxcsr&128))return CW_OPCODE;m->mxcsr|=1;value=b;}
        else {
            x=double_value(a);y=double_value(b);
            value=(op==0x5d?x<y:x>y)?a:b;
        }
        xmm_put(dst,8,value);
        return CW_OK;
    }
    /* The arithmetic path uses default, masked round-to-nearest binary64.
     * Keep unsupported exception/rounding configurations fail-stop. */
    if((m->mxcsr&0xffc0U)!=0x1f80 || (a&FP_EXP)==FP_EXP || (b&FP_EXP)==FP_EXP)return CW_OPCODE;
    x=double_value(a);y=double_value(b);
    switch(op){
    case 0x58:r=x+y;break;
    case 0x59:r=x*y;break;
    case 0x5c:r=x-y;break;
    case 0x5e:if(!y)return CW_OPCODE;r=x/y;break;
    default:return CW_OPCODE;
    }
    value=double_bits(r);
    if((value&FP_EXP)==FP_EXP)return CW_OPCODE;
    xmm_put(dst,8,value);
    return CW_OK;
}

static int packed_integer(Decode *d,unsigned int op,unsigned int reg,Operand o) {
    unsigned char src[16],out[16],*dst=d->m->xmm[reg];
    unsigned int i,width,high,imm=0;
    uint64_t value;
    int status;
    if(op==0x70)imm=(unsigned int)fetch(d,1);
    if(op==0x6e || op==0x7e){
        width=(d->rex&8)?8:4;
        if(op==0x7e)put(d,o,width,xmm_low(dst,width));
        else {
            value=get(d,o,width);
            if(d->error)return d->error;
            memset(dst,0,16);
            xmm_put(dst,width,value);
        }
        return d->error;
    }
    if(op==0xd6)return xmm_write(d,o,dst,8,1);
    status=xmm_read(d,o,src,16);
    if(status)return status;
    if(op==0x70){
        for(i=0;i<4;i++)memcpy(out+i*4,src+((imm>>(i*2))&3)*4,4);
    }else if((op>=0x60 && op<=0x62) || (op>=0x68 && op<=0x6a) || op==0x6c || op==0x6d){
        width=op>=0x6c?8:1U<<(op&3);
        high=(op>=0x68 && op<=0x6a) || op==0x6d?8:0;
        for(i=0;i<8;i+=width){
            memcpy(out+2*i,dst+high+i,width);
            memcpy(out+2*i+width,src+high+i,width);
        }
    }else if(op>=0x74 && op<=0x76){
        width=1U<<(op-0x74);
        for(i=0;i<16;i+=width)memset(out+i,!memcmp(dst+i,src+i,width)?255:0,width);
    }else{
        for(i=0;i<16;i++){
            if(op==0x54 || op==0xdb)out[i]=dst[i]&src[i];
            else if(op==0x55 || op==0xdf)out[i]=(unsigned char)(~dst[i]&src[i]);
            else if(op==0x56 || op==0xeb)out[i]=dst[i]|src[i];
            else out[i]=dst[i]^src[i];
        }
    }
    memcpy(dst,out,16);
    return CW_OK;
}

static int tick(CwMachine *m,int windows_bootstrap) {
    Decode d;Operand o,q;unsigned int op,n,reg=0,group=0,prefixes=0;
    uint64_t a,b,v,target=0;int jump=0;
    memset(&d,0,sizeof(d));d.m=m;d.start=d.cur=m->ip;
    op=(unsigned int)fetch(&d,1);
    while((op>=0x40 && op<=0x4f) || op==0x66 || op==0xf2 || op==0xf3 || op==0x65 || op==0x67 || op==0x2e || op==0xf0) {
        if(++prefixes>14){d.error=CW_OPCODE;break;}
        if(op>=0x40 && op<=0x4f){if(d.rex){d.error=CW_OPCODE;break;}d.rex=op;}
        else if(op==0x65 || op==0x2e){if(d.rex){d.error=CW_OPCODE;break;}d.gs=op==0x65;}
        else if(op==0x67){if(d.rex){d.error=CW_OPCODE;break;}d.addr32=1;}
        else if(op==0xf0){if(d.locked || d.rex){d.error=CW_OPCODE;break;}d.locked=1;}
        else {if((d.prefix && !(op==0x66 && d.prefix==0x66)) || d.rex){d.error=CW_OPCODE;break;}d.prefix=op;}
        op=(unsigned int)fetch(&d,1);
    }
    n=(d.rex&8)?8:(d.prefix==0x66?2:4);
    if(d.error)return d.error;
    if(d.prefix==0xf2 && op!=0x0f)return CW_OPCODE;
    if(d.prefix==0xf3 && op!=0x0f && op!=0x90 && op!=0xc3 && op!=0xa4 && op!=0xa5 && op!=0xaa && op!=0xab)return CW_OPCODE;
    if(d.locked && op!=0x0f && op!=0x86 && op!=0x87 && op!=0x80 && op!=0x81 && op!=0x83)return CW_OPCODE;
    if(op>=0xb8 && op<=0xbf){v=fetch(&d,n);put(&d,regop(&d,(op-0xb8)+((d.rex&1)?8:0),n),n,v);}
    else if(op>=0xb0 && op<=0xb7){v=fetch(&d,1);put(&d,regop(&d,(op-0xb0)+((d.rex&1)?8:0),1),1,v);}
    else if(op>=0x50 && op<=0x57){if(d.prefix)return CW_OPCODE;push(&d,m->r[(op-0x50)+((d.rex&1)?8:0)]);}
    else if(op>=0x58 && op<=0x5f){if(d.prefix)return CW_OPCODE;v=pop(&d);if(!d.error)m->r[(op-0x58)+((d.rex&1)?8:0)]=v;}
    else if(op==0x68 || op==0x6a){if(d.prefix)return CW_OPCODE;v=op==0x68?(uint64_t)(int64_t)(int32_t)fetch(&d,4):(uint64_t)(int64_t)(int8_t)fetch(&d,1);push(&d,v);}
    else if(op==0x90){
        if(d.rex&1){a=m->r[0]&mask(n);b=m->r[8]&mask(n);put(&d,regop(&d,0,n),n,b);put(&d,regop(&d,8,n),n,a);}
    }
    else if(op==0xc3){
        if(d.rex || (d.prefix && d.prefix!=0xf3))return CW_OPCODE;
        a=m->r[4];v=pop(&d);
        if(windows_bootstrap && !d.error && v>=CW_TLS_RETURN)return cw_bootstrap_return(m,v,a);
        else {jump=1;target=v;}
    }
    else if(op==0xc9){if(d.prefix || d.rex)return CW_OPCODE;m->r[4]=m->r[5];v=pop(&d);if(!d.error)m->r[5]=v;}
    else if(op==0xe8 || op==0xe9 || op==0xeb){if(d.prefix || d.rex)return CW_OPCODE;b=op==0xeb?(uint64_t)(int64_t)(int8_t)fetch(&d,1):(uint64_t)(int64_t)(int32_t)fetch(&d,4);target=d.cur+b;jump=1;if(op==0xe8)push(&d,d.cur);}
    else if(op>=0x70 && op<=0x7f){if(d.prefix || d.rex)return CW_OPCODE;b=(uint64_t)(int64_t)(int8_t)fetch(&d,1);if(condition(m,op&15)){jump=1;target=d.cur+b;}}
    else if(op==0x88 || op==0x89 || op==0x8a || op==0x8b || op==0x8d){
        if(op==0x88 || op==0x8a)n=1;
        o=operand(&d,&reg,&group,n);q=regop(&d,reg,n);
        if(op==0x8d){if(o.reg>=0)return CW_OPCODE;v=o.at+(o.rip?d.cur:0);put(&d,q,n,d.addr32?(uint32_t)v:v);}
        else if(op==0x88 || op==0x89)put(&d,o,n,get(&d,q,n));
        else put(&d,q,n,get(&d,o,n));
    }
    else if(op==0xc6 || op==0xc7){if(op==0xc6)n=1;o=operand(&d,&reg,&group,n);if(group)return CW_OPCODE;v=fetch(&d,n==8?4:n);if(n==8)v=(uint64_t)(int64_t)(int32_t)v;put(&d,o,n,v);}
    else if(op<=0x3d && ((op&7)<=5)) {
        unsigned int kind=op>>3,form=op&7;
        if(!(form&1))n=1;
        if(form<=3){o=operand(&d,&reg,&group,n);q=regop(&d,reg,n);if(form&2){Operand tmp=o;o=q;q=tmp;}a=get(&d,o,n);b=get(&d,q,n);}
        else {o=regop(&d,0,n);b=fetch(&d,n==8?4:n);if(n==8)b=(uint64_t)(int64_t)(int32_t)b;a=get(&d,o,n);}
        v=alu(&d,kind,a,b,n);if(kind!=7)put(&d,o,n,v);
    }
    else if(op==0x80 || op==0x81 || op==0x83){
        if(op==0x80)n=1;
        o=operand(&d,&reg,&group,n);
        b=fetch(&d,op==0x83?1:(n==8?4:n));
        if(d.error)return d.error;
        if(d.locked){
            if(o.reg>=0 || group==7)return CW_OPCODE;
            if(!cw_memory(m,address(&d,o),n,CW_W))return CW_MEMORY;
        }
        if(op==0x83)b=(uint64_t)(int64_t)(int8_t)b;
        else if(n==8)b=(uint64_t)(int64_t)(int32_t)b;
        a=get(&d,o,n);
        if(d.error)return d.error;
        v=alu(&d,group,a,b,n);
        if(group!=7)put(&d,o,n,v);
    }
    else if(op==0xfc || op==0xfd){
        if(d.rex || d.prefix)return CW_OPCODE;
        if(op==0xfc)m->flags&=~UINT64_C(0x400);
        else m->flags|=0x400;
    }
    else if(op==0xa4 || op==0xa5 || op==0xaa || op==0xab){
        unsigned int index_width=d.addr32?4:8;
        uint64_t count=m->r[1]&mask(index_width);
        uint64_t dest=m->r[7]&mask(index_width),source=m->r[6]&mask(index_width);
        int move=op==0xa4 || op==0xa5;
        if(!(op&1))n=1;
        if(d.prefix==0xf3 && !count){m->ip=d.cur;return CW_OK;}
        a=m->r[0]&mask(n);
        if(move){
            memset(&q,0,sizeof(q));q.reg=-1;q.at=source;
            a=guest_read(&d,address(&d,q),n,CW_R);
        }
        writen(&d,dest,n,a);
        if(d.error)return d.error;
        b=(m->flags&0x400)?UINT64_MAX-(n-1):n;
        put(&d,regop(&d,7,index_width),index_width,dest+b);
        if(move)put(&d,regop(&d,6,index_width),index_width,source+b);
        if(d.prefix==0xf3){
            put(&d,regop(&d,1,index_width),index_width,--count);
            if(count){jump=1;target=d.start;} /* Charge each element to the execution budget. */
        }
    }
    else if(op==0xa8 || op==0xa9){if(op==0xa8)n=1;b=fetch(&d,n==8?4:n);if(n==8)b=(uint64_t)(int64_t)(int32_t)b;(void)alu(&d,4,m->r[0],b,n);}
    else if(op==0x84 || op==0x85){if(op==0x84)n=1;o=operand(&d,&reg,&group,n);(void)alu(&d,4,get(&d,o,n),get(&d,regop(&d,reg,n),n),n);}
    else if(op==0x86 || op==0x87){
        if(op==0x86)n=1;
        o=operand(&d,&reg,&group,n);
        if(d.locked && o.reg>=0)return CW_OPCODE;
        if(o.reg<0 && !cw_memory(m,address(&d,o),n,CW_W))return CW_MEMORY;
        a=get(&d,o,n);b=get(&d,regop(&d,reg,n),n);
        put(&d,o,n,b);put(&d,regop(&d,reg,n),n,a);
    }
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
    else if(op==0xfe){ /* INC/DEC r/m8 */
        o=operand(&d,&reg,&group,1);
        if(group>1)return CW_OPCODE;
        a=m->flags&CF;
        v=alu(&d,group?5:0,get(&d,o,1),1,1);
        m->flags=(m->flags&~(uint64_t)CF)|a;
        put(&d,o,1,v);
    }
    else if(op==0xff){o=operand(&d,&reg,&group,n);if(group==2 || group==4 || group==6){if(d.prefix)return CW_OPCODE;v=get(&d,o,8);if(group==6)push(&d,v);else {if(group==2)push(&d,d.cur);jump=1;target=v;}}else if(group<2){a=m->flags&CF;v=alu(&d,group?5:0,get(&d,o,n),1,n);m->flags=(m->flags&~(uint64_t)CF)|a;put(&d,o,n,v);}else return CW_OPCODE;}
    else if(op==0xd9){
        if(d.prefix || d.rex&8)return CW_OPCODE;
        o=operand(&d,&reg,&group,2);
        if(o.reg>=0 || (group!=5 && group!=7))return CW_OPCODE;
        if(group==5)m->x87_control=(uint16_t)get(&d,o,2);
        else put(&d,o,2,m->x87_control);
    }
    else if(op==0xdb){
        unsigned int second=(unsigned int)fetch(&d,1);
        if(second!=0xe3 || d.rex || d.prefix)return CW_OPCODE;
        m->x87_control=0x037f;m->x87_status=0;m->x87_tag=0xffff;m->x87_opcode=0;m->x87_ip=0;m->x87_dp=0;
    }
    else if(op==0x0f){
        unsigned int second=(unsigned int)fetch(&d,1);
        if(d.locked && second!=0xb0 && second!=0xb1 && second!=0xab && second!=0xb3 && second!=0xbb && second!=0xba)return CW_OPCODE;
        if(d.prefix==0xf3 && second!=0x6f && second!=0x7f && second!=0x7e && second!=0xe6)return CW_OPCODE;
        if(d.prefix==0xf2){
            if(second!=0x10 && second!=0x11 && second!=0x2a && second!=0x2c &&
               second!=0x58 && second!=0x59 && second!=0x5c && second!=0x5d &&
               second!=0x5e && second!=0x5f)return CW_OPCODE;
            o=operand(&d,&reg,&group,8);
            d.error=scalar_double(&d,second,reg,o,n);
        }
        else if((second==0xe6 && (d.prefix==0x66 || d.prefix==0xf3)) ||
                (second==0xc2 && d.prefix==0x66)){
            o=operand(&d,&reg,&group,8);
            d.error=packed_double(&d,second,reg,o);
        }
        else if(d.prefix==0x66 && (second==0x2e || second==0x2f)){
            o=operand(&d,&reg,&group,8);
            d.error=scalar_double(&d,second,reg,o,n);
        }
        else if(d.prefix==0xf3 && second==0x7e){
            unsigned char data[8];
            o=operand(&d,&reg,&group,8);
            d.error=xmm_read(&d,o,data,8);
            if(!d.error){memcpy(m->xmm[reg],data,8);memset(m->xmm[reg]+8,0,8);}
        }
        else if((!d.prefix || d.prefix==0x66) && (second==0x12 || second==0x13 || second==0x16 || second==0x17)){
            unsigned char data[8];
            o=operand(&d,&reg,&group,8);
            if(second==0x13 || second==0x17){
                if(o.reg>=0)return CW_OPCODE;
                d.error=xmm_write(&d,o,m->xmm[reg]+(second==0x17?8:0),8,0);
            }else {
                if(o.reg>=0 && d.prefix)return CW_OPCODE;
                if(o.reg>=0)memcpy(data,m->xmm[o.reg]+(second==0x12?8:0),8);
                else d.error=xmm_read(&d,o,data,8);
                if(!d.error)memcpy(m->xmm[reg]+(second==0x16?8:0),data,8);
            }
        }
        else if(((!d.prefix || d.prefix==0x66) && second>=0x54 && second<=0x57) ||
                (d.prefix==0x66 && ((second>=0x60 && second<=0x62) ||
                 ((second>=0x68 && second<=0x6a) || (second>=0x6c && second<=0x6e)) || second==0x70 ||
                 (second>=0x74 && second<=0x76) || second==0x7e ||
                 second==0xd6 || second==0xdb || second==0xdf || second==0xeb || second==0xef))){
            o=operand(&d,&reg,&group,8);
            d.error=packed_integer(&d,second,reg,o);
        }
        else if(d.prefix==0x66 && (second==0x6f || second==0x7f)){
            o=operand(&d,&reg,&group,8);
            if(o.reg<0 && (address(&d,o)&15))return CW_MEMORY;
            if(!d.error)vector(&d,o,reg,second==0x7f);
        }
        else if(second>=0x80 && second<=0x8f){if(d.prefix || d.rex)return CW_OPCODE;b=(uint64_t)(int64_t)(int32_t)fetch(&d,4);if(condition(m,second&15)){jump=1;target=d.cur+b;}}
        else if(second==0xa3 || second==0xab || second==0xb3 || second==0xbb || second==0xba){
            unsigned int operation;
            o=operand(&d,&reg,&group,n);
            if(second==0xba){
                if(group<4)return CW_OPCODE;
                operation=group-4;
                b=fetch(&d,1);
            }else{
                operation=(second-0xa3)/8;
                b=m->r[reg]&mask(n);
                if(o.reg<0){
                    int64_t index=(int64_t)sign_extend(b,n);
                    int64_t width=(int64_t)n*8;
                    int64_t words=index/width-(index%width<0);
                    o.at+=(uint64_t)words*n;
                }
            }
            if(d.error)return d.error;
            if(d.locked && (!operation || o.reg>=0))return CW_OPCODE;
            if(operation && o.reg<0 && !cw_memory(m,address(&d,o),n,CW_W))return CW_MEMORY;
            a=get(&d,o,n);
            if(d.error)return d.error;
            b=UINT64_C(1)<<(b&(n*8-1));
            m->flags=(m->flags&~(uint64_t)CF)|((a&b)?CF:0);
            if(operation)put(&d,o,n,operation==1?a|b:operation==2?a&~b:a^b);
        }
        else if(second==0xb0 || second==0xb1){
            if(second==0xb0)n=1;
            o=operand(&d,&reg,&group,n);
            if(d.locked && o.reg>=0)return CW_OPCODE;
            if(o.reg<0 && !cw_memory(m,address(&d,o),n,CW_W))return CW_MEMORY;
            a=get(&d,regop(&d,0,n),n);b=get(&d,o,n);
            if(d.error)return d.error;
            (void)alu(&d,7,a,b,n);
            if(a==b)put(&d,o,n,get(&d,regop(&d,reg,n),n));
            else put(&d,regop(&d,0,n),n,b);
        }
        else if(second==0xaf){uint64_t high;o=operand(&d,&reg,&group,n);product(get(&d,regop(&d,reg,n),n),get(&d,o,n),n,1,&v,&high);multiply_flags(&d,v,high,n,1);put(&d,regop(&d,reg,n),n,v);}
        else if(second==0xbe || second==0xbf){unsigned int small=second==0xbe?1:2;o=operand(&d,&reg,&group,small);put(&d,regop(&d,reg,n),n,sign_extend(get(&d,o,small),small));}
        else if(second==0xb6 || second==0xb7){unsigned int small=second==0xb6?1:2;o=operand(&d,&reg,&group,small);put(&d,regop(&d,reg,n),n,get(&d,o,small));}
        else if(second==0xae && !d.prefix && !d.rex){
            /* Guest execution is single-threaded and memory accesses are ordered. */
            if(fetch(&d,1)!=0xf0)return CW_OPCODE; /* MFENCE */
        }
        else if(second>=0xc8 && second<=0xcf && !d.prefix){ /* BSWAP */
            unsigned int i;
            reg=(second&7)+((d.rex&1)?8:0);
            a=m->r[reg];
            v=0;
            for(i=0;i<n;i++)v=(v<<8)|((a>>(8*i))&255);
            put(&d,regop(&d,reg,n),n,v);
        }
        else if(second==0x3a && d.prefix==0x66){
            unsigned int lane,width=(d.rex&8)?8:4;
            if(fetch(&d,1)!=0x22)return CW_OPCODE; /* PINSRD/PINSRQ */
            o=operand(&d,&reg,&group,width);
            lane=(unsigned int)fetch(&d,1)&(16/width-1);
            v=get(&d,o,width);
            if(!d.error)xmm_put(m->xmm[reg]+lane*width,width,v);
        }
        else if(second==0xfe && d.prefix==0x66){ /* PADDD */
            unsigned char source[16];
            unsigned int i;
            o=operand(&d,&reg,&group,8);
            if(o.reg<0 && (address(&d,o)&15))return CW_MEMORY;
            d.error=xmm_read(&d,o,source,16);
            if(!d.error)for(i=0;i<16;i+=4)
                xmm_put(m->xmm[reg]+i,4,xmm_low(m->xmm[reg]+i,4)+xmm_low(source+i,4));
        }
        else if(second==0x50 && (!d.prefix || d.prefix==0x66)){
            unsigned int stride=d.prefix==0x66?8:4;
            unsigned int i;
            o=operand(&d,&reg,&group,8);
            if(o.reg<0)return CW_OPCODE;
            v=0;
            for(i=0;i<16/stride;i++)v|=(uint64_t)(m->xmm[o.reg][(i+1)*stride-1]>>7)<<i;
            put(&d,regop(&d,reg,4),4,v);
        }
        else if(second>=0x90 && second<=0x9f){o=operand(&d,&reg,&group,1);put(&d,o,1,(uint64_t)condition(m,second&15));}
        else if(second>=0x40 && second<=0x4f){o=operand(&d,&reg,&group,n);v=get(&d,o,n);if(condition(m,second&15))put(&d,regop(&d,reg,n),n,v);}
        else if((second==0x10 || second==0x11 || second==0x28 || second==0x29) && (!d.prefix || d.prefix==0x66)) {
            o=operand(&d,&reg,&group,8);
            if((second==0x28 || second==0x29) && o.reg<0 && (address(&d,o)&15))return CW_MEMORY;
            if(!d.error)vector(&d,o,reg,second==0x11 || second==0x29);
        }
        else if((second==0x6f || second==0x7f) && d.prefix==0xf3){o=operand(&d,&reg,&group,8);if(!d.error)vector(&d,o,reg,second==0x7f);}
        else if(second==0x1f){o=operand(&d,&reg,&group,n);if(group)return CW_OPCODE;}
        else return CW_OPCODE; /* SYSCALL/SYSENTER, privileged and unknown opcodes fail closed. */
    }
    else return CW_OPCODE;
    if(d.error)return d.error;
    m->ip=jump?target:d.cur;return CW_OK;
}
int cw_cpu_step(CwMachine *m) {
    return tick(m,0);
}

int cw_run(CwMachine *m,uint32_t budget) {
    if(!m || !m->image || !m->stack)return CW_HEADER;
    if(m->status)return m->status;
    if(m->exited)return CW_OK;
    if(!budget || budget>CW_STEP_LIMIT(m->plan.profile_flags)){cw_files_close_all(m);return m->status=CW_BUDGET;}
    while(m->instructions<budget){int status;if(m->ip<CW_THUNK_BASE)m->last_guest_ip=m->ip;m->instructions++;status=m->ip>=CW_THUNK_BASE?cw_api_dispatch(m):tick(m,1);if(status){cw_files_close_all(m);return m->status=status;}if(m->exited){cw_files_close_all(m);return CW_OK;}}
    cw_files_close_all(m);return m->status=CW_BUDGET;
}

const char *cw_status_name(int status) {
    static const char *const names[]={"ok","bad-header","unsupported-image","bounds","unsafe-mapping","bad-relocation","memory-fault","unsupported-opcode","instruction-budget","abi-violation","api-policy","integer-divide-error","crt-contract","unimplemented-export"};
    return status>=0 && (unsigned int)status<sizeof(names)/sizeof(names[0])?names[status]:"unknown";
}
