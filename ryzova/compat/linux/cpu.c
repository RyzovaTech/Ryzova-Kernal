/* SPDX-License-Identifier: AGPL-3.0-only */
/* Bounded integer AMD64 interpreter. Unsupported encodings fail closed. */
#include "process.h"
#define CF 1U
#define PF 4U
#define AF 16U
#define ZF 64U
#define SF 128U
#define OF 2048U
typedef RyzCpu Cpu;
static uint32_t cpu_limit(Cpu *c){return c->result->instruction_limit?c->result->instruction_limit:RYZ_PROCESS_STEPS;}
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
    if(!ryz_memory_access(c->m,at,size,RYZ_WRITE|256U)){ c->fault=1; return; }
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
    return load(c,address(c,o)+c->segment,size,RYZ_READ);
}
static void put(Cpu *c,Operand o,unsigned int size,uint64_t v)
{
    uint64_t bits=mask(size);
    unsigned int shift=o.high?8:0;
    if(c->fault)return;
    if(o.reg<0) store(c,address(c,o)+c->segment,size,v);
    else if(size==4 || size==8) c->r[o.reg]=v&bits;
    else c->r[o.reg]=(c->r[o.reg]&~(bits<<shift))|((v&bits)<<shift);
}
static void vector_move(Cpu *c,Operand operand,unsigned int reg,int to_operand)
{
    unsigned char temporary[16];
    uint64_t at;
    unsigned int i;
    if(c->fault)return;
    if(to_operand){
        for(i=0;i<16;i++)temporary[i]=c->xmm[reg][i];
        if(operand.reg>=0){for(i=0;i<16;i++)c->xmm[operand.reg][i]=temporary[i];}
        else{
            at=address(c,operand)+c->segment;
            if(!ryz_memory_access(c->m,at,16,RYZ_WRITE|256U)){c->fault=1;return;}
            memcpy(c->m->bytes+(size_t)(at-c->m->base),temporary,16);
        }
    }else{
        if(operand.reg>=0){for(i=0;i<16;i++)temporary[i]=c->xmm[operand.reg][i];}
        else{
            at=address(c,operand)+c->segment;
            if(!ryz_memory_access(c->m,at,16,RYZ_READ)){c->fault=1;return;}
            memcpy(temporary,c->m->bytes+(size_t)(at-c->m->base),16);
        }
        for(i=0;i<16;i++)c->xmm[reg][i]=temporary[i];
    }
}
static void vector_xor(Cpu *c, Operand o, unsigned int reg)
{
    unsigned char data[16];
    uint64_t at;
    unsigned int i;
    if(c->fault)return;
    if(o.reg>=0)memcpy(data,c->xmm[o.reg],16);
    else{
        at=address(c,o)+c->segment;
        if(!ryz_memory_access(c->m,at,16,RYZ_READ)){c->fault=1;return;}
        memcpy(data,c->m->bytes+(size_t)(at-c->m->base),16);
    }
    for(i=0;i<16;i++)c->xmm[reg][i]^=data[i];
}
/* SSE2 POR is a 128-bit bitwise union. No EFLAGS are modified. */
static void vector_or(Cpu *c, Operand o, unsigned int reg)
{
    unsigned char data[16];
    uint64_t at;
    unsigned int i;
    if(c->fault)return;
    if(o.reg>=0)memcpy(data,c->xmm[o.reg],16);
    else{
        at=address(c,o)+c->segment;
        /* Legacy SSE2 POR m128 requires a 16-byte aligned operand.
         * Linux raises #GP on misalignment; the VM must fail closed. */
        if(at&15U){c->fault=1;return;}
        if(!ryz_memory_access(c->m,at,16,RYZ_READ)){c->fault=1;return;}
        memcpy(data,c->m->bytes+(size_t)(at-c->m->base),16);
    }
    for(i=0;i<16;i++)c->xmm[reg][i]|=data[i];
}
/* IEEE-754 binary32 conversion for the *default RN-even mode* of CVTSI2SS.
 * No host floating point, x87 host rounding or fabricated target output.
 * x86 MXCSR modifications are unsupported by this finite interpreter,
 * so non-default guest rounding/exception behavior is NOT qualified. */
static uint32_t convert_signed_binary32(uint64_t raw,unsigned int width)
{
    uint64_t magnitude,kept,lost,half,parts;
    unsigned int sign,bit,drop,exponent;
    raw&=mask(width);
    sign=(unsigned int)(raw>>(width*8U-1U));
    magnitude=sign?((~raw)&mask(width))+1U:raw;
    if(!magnitude)return 0;
    bit=0;
    {uint64_t v=magnitude;while(v>>=1U)bit++;}
    exponent=bit+127U;
    if(bit<=23U)kept=magnitude<<(23U-bit);
    else{
        drop=bit-23U;
        kept=magnitude>>drop;
        parts=(UINT64_C(1)<<drop)-1U;
        lost=magnitude&parts;
        half=UINT64_C(1)<<(drop-1U);
        if(lost>half || (lost==half && (kept&1U)))kept++;
        if(kept==(UINT64_C(1)<<24U)){kept>>=1;exponent++;}
    }
    return ((uint32_t)sign<<31U)|((uint32_t)exponent<<23U)|
           ((uint32_t)kept&UINT32_C(0x7fffff));
}
/* Default RN-even scalar binary32 division via integer mantissas.
 * Does not use host FP; non-default MXCSR/exception flags unqualified. */
static uint32_t divide_binary32(uint32_t left,uint32_t right)
{
    uint32_t sign=(left^right)&UINT32_C(0x80000000);
    unsigned int ea=(left>>23U)&255U,eb=(right>>23U)&255U;
    uint32_t ma=left&UINT32_C(0x7fffff),mb=right&UINT32_C(0x7fffff);
    int expa,expb,exponent,shift;
    uint64_t numerator,denominator,q,r;
    if(ea==255U && ma)return left|UINT32_C(0x00400000);
    if(eb==255U && mb)return right|UINT32_C(0x00400000);
    if((ea==255U && eb==255U) ||
       (ea==0U && ma==0U && eb==0U && mb==0U))
        return UINT32_C(0xffc00000);
    if(ea==255U || (eb==0U && mb==0U))
        return sign|UINT32_C(0x7f800000);
    if((ea==0U && ma==0U) || eb==255U)return sign;
    expa=ea?(int)ea-127:-126;
    expb=eb?(int)eb-127:-126;
    if(ea)ma|=UINT32_C(1)<<23U;
    if(eb)mb|=UINT32_C(1)<<23U;
    while(ma<(UINT32_C(1)<<23U)){ma<<=1U;expa--;}
    while(mb<(UINT32_C(1)<<23U)){mb<<=1U;expb--;}
    exponent=expa-expb;
    if(ma<mb){ma<<=1U;exponent--;}
    numerator=(uint64_t)ma<<23U;
    if(exponent>=-126){
        denominator=mb;q=numerator/denominator;r=numerator%denominator;
        if(r*2U>denominator || (r*2U==denominator && (q&1U)))q++;
        if(q==(UINT64_C(1)<<24U)){q>>=1U;exponent++;}
        if(exponent>127)return sign|UINT32_C(0x7f800000);
        return sign|((uint32_t)(exponent+127)<<23U)|((uint32_t)q&UINT32_C(0x7fffff));
    }
    shift=-126-exponent;
    if(shift>=32)return sign;
    denominator=(uint64_t)mb<<(unsigned int)shift;
    q=numerator/denominator;r=numerator%denominator;
    if(r*2U>denominator || (r*2U==denominator && (q&1U)))q++;
    if(q>=(UINT64_C(1)<<23U))return sign|UINT32_C(0x00800000);
    return sign|(uint32_t)q;
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
    uint64_t carryin=(group==2 || group==3)?((c->flags&CF)!=0):0;
    a&=bits; b&=bits;
    if(group==0 || group==2){
        full=a+b; v=(full+carryin)&bits;
        carry=size==8?(full<a || v<(full&bits)):(full+carryin)>bits;
        overflow=(~(a^b)&(a^v)&sign)!=0;
        adjust=((a^b^v)&16)!=0;
    }else if(group==5 || group==7 || group==3){
        v=(a-b-carryin)&bits; carry=a<b || (carryin && a==b);
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
static uint64_t multiply(Cpu *c,uint64_t a,uint64_t b,unsigned int size)
{
    uint64_t bits=mask(size), sign=UINT64_C(1)<<(size*8-1), am,bm,limit,value;
    int negative;
    a&=bits;b&=bits;negative=((a^b)&sign)!=0;
    am=(a&sign)?(-a)&bits:a;bm=(b&sign)?(-b)&bits:b;
    limit=negative?sign:sign-1;
    value=(a*b)&bits;
    c->flags&=~(uint64_t)(CF|OF);
    if(bm!=0 && am>limit/bm)c->flags|=CF|OF;
    return value;
}
static void multiply_pair(Cpu *c,uint64_t b,unsigned int size,int is_signed)
{
    uint64_t bits=mask(size),a=c->r[0]&bits,low,high,t,w0,w1,w2,sign=UINT64_C(1)<<(size*8-1);
    b&=bits;
    if(size<8){t=a*b;low=t&bits;high=(t>>(size*8))&bits;}
    else{
        w0=(a&mask(4))*(b&mask(4));
        t=(a>>32)*(b&mask(4))+(w0>>32);w1=t&mask(4);w2=t>>32;
        w1+=(a&mask(4))*(b>>32);
        high=(a>>32)*(b>>32)+w2+(w1>>32);low=(w1<<32)|(w0&mask(4));
    }
    if(is_signed){if(a&sign)high=(high-b)&bits;if(b&sign)high=(high-a)&bits;}
    c->flags&=~(uint64_t)(CF|OF);
    if(is_signed?(high!=((low&sign)?bits:0)):(high!=0))c->flags|=CF|OF;
    if(size==1)put(c,regop(c,0,2),2,low|(high<<8));
    else{put(c,regop(c,0,size),size,low);put(c,regop(c,2,size),size,high);}
}
static int divide(Cpu *c, uint64_t divisor, unsigned int size, int is_signed)
{
    unsigned int n=size*8, i;
    uint64_t bits=mask(size), sign=UINT64_C(1)<<(n-1), low,high,q=0,r,bit;
    int negative=0, dnegative=0;
    low=c->r[0]&bits; high=size==1?(c->r[0]>>8)&255:c->r[2]&bits;
    divisor&=bits;
    if(divisor==0)return 0;
    if(is_signed){
        negative=(high&sign)!=0; dnegative=(divisor&sign)!=0;
        if(negative){ low=(-low)&bits;high=(~high+(low==0))&bits; }
        if(dnegative)divisor=(-divisor)&bits;
    }
    if(high>=divisor)return 0;
    r=high;
    for(i=n;i>0;i--){
        bit=r>>(n-1);r=((r<<1)|((low>>(i-1))&1))&bits;
        if(bit || r>=divisor){r=(r-divisor)&bits;q|=UINT64_C(1)<<(i-1);}
    }
    if(is_signed){
        if(q>((negative!=dnegative)?sign:sign-1))return 0;
        if(negative!=dnegative)q=(-q)&bits;
        if(negative)r=(-r)&bits;
    }
    put(c,regop(c,0,size),size,q);
    if(size==1)c->r[0]=(c->r[0]&~UINT64_C(0xff00))|(r<<8);
    else put(c,regop(c,2,size),size,r);
    return 1;
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
    uint64_t nr=c->r[0], value;
    int64_t answer;
    if(nr==98){
        /* Linux x86_64 getrusage (RUSAGE_SELF only). This is logical
         * *virtual guest* CPU accounting, not physical host timing/RSS.
         * 1 executed guest instruction = 1 virtual nanosecond; all
         * unmeasured counters stay zero instead of inventing host use.
         * Do not forward any resource query to the host kernel. */
        answer=-22; /* EINVAL for unsupported who */
        if(c->r[7]==0){
            if(!ryz_memory_access(c->m,c->r[6],144,RYZ_WRITE|256U))
                answer=-14; /* EFAULT without partial guest writes */
            else{
                unsigned char *out=c->m->bytes+(size_t)(c->r[6]-c->m->base);
                uint64_t usec=(uint64_t)c->result->executed_steps/1000U;
                memset(out,0,144);
                store(c,c->r[6],8,usec/1000000U);
                store(c,c->r[6]+8,8,usec%1000000U);
                answer=c->fault?-14:0;
            }
        }
        c->r[1]=c->cur;c->r[11]=c->flags;c->r[0]=(uint64_t)answer;
        c->result->syscall_count++;
        return RYZ_VM_OK;
    }
    if(nr==158 || nr==218){
        answer=-22;
        if(nr==218){
            if(c->r[7]==0 || ryz_memory_access(c->m,c->r[7],4,RYZ_WRITE)){
                c->tid_address=c->r[7]; answer=(int64_t)c->p->ns.pid;
            }else answer=-14;
        }else if(c->r[7]==0x1002 || c->r[7]==0x1001){
            value=c->r[6];
            if(value==0 || ryz_memory_access(c->m,value,1,RYZ_READ)){
                if(c->r[7]==0x1002)c->fsbase=value;else c->gsbase=value;
                answer=0;
            }else answer=-1;
        }else if(c->r[7]==0x1003 || c->r[7]==0x1004){
            if(ryz_memory_access(c->m,c->r[6],8,RYZ_WRITE)){
                store(c,c->r[6],8,c->r[7]==0x1003?c->fsbase:c->gsbase); answer=0;
            }else answer=-14;
        }
        c->r[1]=c->cur;c->r[11]=c->flags;c->r[0]=(uint64_t)answer;
        c->result->syscall_count++;
        return RYZ_VM_OK;
    }
    r.rax=nr;r.rdi=c->r[7];r.rsi=c->r[6];r.rdx=c->r[2];r.r10=c->r[10];r.r8=c->r[8];r.r9=c->r[9];
    if((nr==97 || nr==160 || nr==302 || nr==109 || nr==112 || nr==121 || nr==124 || nr==7 || nr==56 || nr==202 || nr==273 || nr==274 || nr==24 || nr==60 || nr==231 || nr==15 || nr==35 || nr==36 || nr==37 || nr==38 || nr==128 || nr==230 || nr==34 || nr==57 || nr==58 || nr==59 || nr==61 || nr==62 || nr==127 || nr==130 || nr==131 || nr==200 || nr==234) && c->p->job_call){
        int state=c->p->job_call(c->p->job_context,c,&r,&answer);
        if(state==RYZ_CPU_BLOCKED)return state;
        if(state==RYZ_CPU_EXECUTED){c->result->syscall_count++;return RYZ_VM_OK;}
        if(state!=RYZ_VM_OK){
            if(state==RYZ_VM_SYSCALL_UNSUPPORTED){c->result->unsupported_syscall_nr=nr;c->result->unsupported_syscall_valid=1;}
            return state;
        }
        c->r[1]=c->cur;c->r[11]=c->flags;c->r[0]=(uint64_t)answer;c->result->syscall_count++;return RYZ_VM_OK;
    }
    if((nr==22 || nr==293) && c->p->world){
        answer=ryz_linux_syscall(c->p,&r);
        if(answer==RYZ_LINUX_BLOCKED)return RYZ_CPU_BLOCKED;
        c->r[1]=c->cur;c->r[11]=c->flags;c->r[0]=(uint64_t)answer;c->result->syscall_count++;return RYZ_VM_OK;
    }
    if(!(c->p->world && (nr==21 || nr==26 || nr==74 || nr==75 || nr==76 || nr==77 || nr==81 || nr==82 || nr==83 || nr==84 || nr==86 || nr==265 || nr==87 || nr==88 || nr==89 || nr==266 || nr==267 || nr==90 || nr==91 || nr==95 || nr==217 || nr==258 || nr==263 || nr==280 || nr==228 || nr==229 || nr==201 || nr==318 || nr==324 || nr==19 || (c->p->world->resources && (nr==17 || nr==18 || (nr==157 && r.rdi==RYZ_FS_RESTRICT))) || (nr>=41 && nr<=55) || nr==288)) && nr!=7 && nr!=32 && nr!=33 && nr!=292 && nr!=40 && nr!=2 && nr!=8 && nr!=80 && nr!=63 && nr!=79 && nr!=105 && nr!=106 && nr!=117 && nr!=119 && nr!=13 && nr!=14 && nr!=110 && nr!=111 && nr!=4 && nr!=5 && nr!=6 && nr!=262 && nr!=107 && nr!=108 && nr!=0 && nr!=1 && nr!=3 && nr!=9 && nr!=10 && nr!=11 && nr!=12 &&
       nr!=16 && nr!=20 && nr!=72 && nr!=39 && nr!=60 && nr!=102 && nr!=104 && nr!=186 && nr!=231 && nr!=257)
        {c->result->unsupported_syscall_nr=nr;c->result->unsupported_syscall_valid=1;return RYZ_VM_SYSCALL_UNSUPPORTED;}
    r.rax=nr; r.rdi=c->r[7]; r.rsi=c->r[6]; r.rdx=c->r[2];
    r.r10=c->r[10]; r.r8=c->r[8]; r.r9=c->r[9];
    answer=ryz_linux_syscall(c->p,&r);
    if(answer==RYZ_LINUX_BLOCKED)return RYZ_CPU_BLOCKED;
    c->r[1]=c->cur; c->r[11]=c->flags;
    c->r[0]=(uint64_t)answer;
    c->result->syscall_count++;
    return RYZ_VM_OK;
}
static int step(Cpu *c)
{
    unsigned int op, op2=0, n, reg=0, group=0, size, type, count;
    uint64_t a,b,v=0,target=0,saved;
    int jump=0, rv, locked=0;
    Operand rm, rr;
    c->cur=c->ip; c->rex=c->rex_present=0; c->size=4;
    c->repeat=0;c->operand16=0; c->segment=0;
    for(;;){
        op=(unsigned int)fetch(c,1);
        if(c->fault)return RYZ_VM_MAP_ERROR;
        if(op>=0x40 && op<=0x4f){c->rex=op&15;c->rex_present=1;continue;}
        if(op==0xf0 || op==0x66 || op==0xf3 || op==0xf2 || op==0x2e || op==0x3e ||
           op==0x26 || op==0x36 || op==0x64 || op==0x65){
            c->rex=c->rex_present=0;
            if(op==0xf0)locked=1;
            if(op==0x66){c->size=2;c->operand16=1;}
            if(op==0xf3 || op==0xf2)c->repeat=(int)op;
            if(op==0x2e || op==0x3e || op==0x26 || op==0x36)c->segment=0;
            if(op==0x64)c->segment=c->fsbase;
            if(op==0x65)c->segment=c->gsbase;
            continue;
        }
        break;
    }
    if(c->rex&8)c->size=8;
    if(c->fault) return RYZ_VM_MAP_ERROR;
    size=c->size;
    if(locked && !(op<=0x31 && ((op&7)<=1)) && op!=0xfe && op!=0xff && op!=0x86 && op!=0x87 && op!=0x09 && op!=0x80 && op!=0x81 && op!=0x83 && op!=0x0f)return RYZ_VM_OPCODE_UNSUPPORTED;
    if(size==2 && ((op>=0x50 && op<=0x5f) || op==0x68 || op==0x6a ||
                   op==0xe8 || op==0xc3 || op==0xc9 || op==0x63))
        return RYZ_VM_OPCODE_UNSUPPORTED;
    if(op==0xf8)c->flags&=~UINT64_C(1);
    else if(op==0xf9)c->flags|=1;
    else if(op==0xf5)c->flags^=1;
    else if(op==0x9c)push(c,c->flags);
    else if(op==0x9d){v=pop(c);if(!c->fault)c->flags=(v&UINT64_C(0x250dd5))|0x202;}
    else if(op==0xfc)c->flags&=~UINT64_C(1024);
    else if(op==0xfd)c->flags|=1024;
    else if(op==0xaa || op==0xab || op==0xa4 || op==0xa5){
        uint64_t iterations=c->repeat?c->r[1]:1, j, delta;
        if(op==0xaa || op==0xa4)size=1;
        if(iterations>cpu_limit(c)-c->result->executed_steps)
            return RYZ_VM_STEP_LIMIT;
        delta=(c->flags&1024)?(uint64_t)-(int64_t)size:size;
        for(j=0;j<iterations;j++){
            a=op==0xaa || op==0xab?c->r[0]:load(c,c->r[6]+c->segment,size,RYZ_READ);
            if(c->fault)break;
            store(c,c->r[7],size,a);
            if(c->fault)break;
            c->r[7]+=delta;
            if(op==0xa4 || op==0xa5)c->r[6]+=delta;
            if(c->repeat)c->r[1]--;
            c->extra_steps++;
        }
    }
    else if(op>=0x50 && op<=0x57) push(c,c->r[op-0x50+((c->rex&1)?8:0)]);
    else if(op>=0x58 && op<=0x5f){ v=pop(c); if(!c->fault)c->r[op-0x58+((c->rex&1)?8:0)]=v; }
    else if(op==0x68 || op==0x6a){ v=fetch(c,op==0x68?4:1); v=op==0x68?(uint64_t)(int64_t)(int32_t)v:(uint64_t)(int64_t)(int8_t)v; push(c,v); }
    else if(op>=0xb8 && op<=0xbf){ v=fetch(c,size); put(c,regop(c,op-0xb8+((c->rex&1)?8:0),size),size,v); }
    else if(op>=0xb0 && op<=0xb7){ v=fetch(c,1); put(c,regop(c,op-0xb0+((c->rex&1)?8:0),1),1,v); }
    else if(op==0x86 || op==0x87){
        if(op==0x86)size=1;
        rm=decode(c,&reg,&group,size);rr=regop(c,reg,size);
        if(locked && rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED;
        if(rm.reg<0 && !ryz_memory_access(c->m,address(c,rm)+c->segment,size,RYZ_READ|RYZ_WRITE))return RYZ_VM_MAP_ERROR;
        a=get(c,rm,size);b=get(c,rr,size);
        if(!c->fault){put(c,rm,size,b);put(c,rr,size,a);}
    }
    else if(op==0x88 || op==0x89 || op==0x8a || op==0x8b || op==0x8d){
        if(op==0x88 || op==0x8a) size=1;
        rm=decode(c,&reg,&group,size); rr=regop(c,reg,size);
        if(locked && rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED;
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
    }else if(op==0x69 || op==0x6b){
        rm=decode(c,&reg,&group,size);
        b=fetch(c,op==0x6b?1:(size==8?4:size));
        if(op==0x6b)b=(uint64_t)(int64_t)(int8_t)b;
        else if(size==8)b=(uint64_t)(int64_t)(int32_t)b;
        a=get(c,rm,size);
        if(!c->fault)put(c,regop(c,reg,size),size,multiply(c,a,b,size));
    }else if((op<=0x3b && ((op&7)<=3)) || op==0x84 || op==0x85){
        type=op==0x84 || op==0x85?8:op>>3;
        if((op&1)==0)size=1;
        rm=decode(c,&reg,&group,size); rr=regop(c,reg,size);
        if(locked && rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED;
        if((op&2) && type!=8){ Operand tmp=rm; rm=rr; rr=tmp; }
        a=get(c,rm,size); b=get(c,rr,size);
        if(!c->fault){ v=arithmetic(c,type,a,b,size); if(type!=7 && type!=8)put(c,rm,size,v); }
    }else if(op==0x80 || op==0x81 || op==0x83){
        if(op==0x80)size=1;
        rm=decode(c,&reg,&group,size);
        if(locked && (rm.reg>=0 || group==7))return RYZ_VM_OPCODE_UNSUPPORTED;
        b=fetch(c,op==0x83?1:(size==8?4:size));
        if(op==0x83)b=(uint64_t)(int64_t)(int8_t)b;
        else if(size==8)b=(uint64_t)(int64_t)(int32_t)b;
        a=get(c,rm,size);
        if(!c->fault){ v=arithmetic(c,group,a,b,size); if(group!=7)put(c,rm,size,v); }
    }else if(op==0x04 || op==0x05 || op==0x0c || op==0x0d || op==0x24 || op==0x25 ||
             op==0x14 || op==0x15 || op==0x1c || op==0x1d || op==0x2c || op==0x2d || op==0x34 || op==0x35 || op==0x3c || op==0x3d || op==0xa8 || op==0xa9){
        if((op&1)==0)size=1;
        type=(op==0xa8 || op==0xa9)?8:op>>3;
        b=fetch(c,size==8?4:size); if(size==8)b=(uint64_t)(int64_t)(int32_t)b;
        rr=regop(c,0,size); a=get(c,rr,size);
        if(!c->fault){ v=arithmetic(c,type,a,b,size); if(type!=7 && type!=8)put(c,rr,size,v); }
    }else if(op==0xc0 || op==0xc1 || op==0xd0 || op==0xd1 || op==0xd2 || op==0xd3){
        if(op==0xc0 || op==0xd0 || op==0xd2)size=1;
        rm=decode(c,&reg,&group,size);
        if(group!=0 && group!=1 && group!=4 && group!=5 && group!=7)return RYZ_VM_OPCODE_UNSUPPORTED;
        count=op==0xc0 || op==0xc1?(unsigned int)fetch(c,1):(op==0xd0 || op==0xd1?1:(unsigned int)c->r[1]);
        count&=size==8?63:31; a=get(c,rm,size); n=size*8;
        if(count!=0 && !c->fault && group<=1){
            unsigned int rotate=count%n;
            v=a;
            if(rotate)v=group==0?((a<<rotate)|(a>>(n-rotate))):((a>>rotate)|(a<<(n-rotate)));
            v&=mask(size);c->flags&=~(uint64_t)CF;
            type=group==0?(unsigned int)(v&1):(unsigned int)(v>>(n-1));
            if(type)c->flags|=CF;
            if(count==1){c->flags&=~(uint64_t)OF;if(group==0?(((v>>(n-1))&1)!=type):(((v>>(n-1))^(v>>(n-2)))&1))c->flags|=OF;}
            put(c,rm,size,v);
        }else if(count!=0 && !c->fault){
            saved=c->flags; b=(a>>(n-1))&1;
            if(group==4){ v=count>=n?0:a<<count; type=count>n?0:(unsigned int)((a>>(n-count))&1); }
            else { type=count>n?0:(unsigned int)((a>>(count-1))&1); v=count>=n?0:a>>count;
                if(group==7 && b) v|=count>=n?mask(size):mask(size)^(mask(size)>>count); }
            v=resultflags(c,v,size); if(type)c->flags|=CF;
            if(count==1 && ((group==4 && (((v>>(n-1))&1)!=type)) || (group==5 && b)))c->flags|=OF;
            (void)saved; put(c,rm,size,v);
        }
    }else if(op==0xfe || op==0xff){
        if(op==0xfe)size=1;
        rm=decode(c,&reg,&group,op==0xfe?1:8);
        if(locked && (group>1 || rm.reg>=0))return RYZ_VM_OPCODE_UNSUPPORTED;
        if(op==0xfe && group>1)return RYZ_VM_OPCODE_UNSUPPORTED;
        if(group<=1){ a=get(c,rm,size); saved=c->flags&CF; v=arithmetic(c,group==0?0:5,a,1,size); c->flags=(c->flags&~(uint64_t)CF)|saved; if(!c->fault)put(c,rm,size,v); }
        else if(group==2 || group==4){ if(size==2)return RYZ_VM_OPCODE_UNSUPPORTED; target=get(c,rm,8); if(group==2 && !c->fault)push(c,c->cur); jump=1; }
        else if(group==6){ if(size==2)return RYZ_VM_OPCODE_UNSUPPORTED; a=get(c,rm,8); if(!c->fault)push(c,a); }
        else return RYZ_VM_OPCODE_UNSUPPORTED;
    }else if(op==0xf6 || op==0xf7){
        if(op==0xf6)size=1;
        rm=decode(c,&reg,&group,size);
        if(group==0){ b=fetch(c,size==8?4:size); if(size==8)b=(uint64_t)(int64_t)(int32_t)b; a=get(c,rm,size); if(!c->fault)arithmetic(c,8,a,b,size); }
        else if(group==2 || group==3){ a=get(c,rm,size); if(!c->fault){ v=group==2?~a:arithmetic(c,5,0,a,size); put(c,rm,size,v); } }
        else if(group==4 || group==5){
            a=get(c,rm,size);if(!c->fault)multiply_pair(c,a,size,group==5);
        }
        else if(group==6 || group==7){
            a=get(c,rm,size);
            if(!c->fault && !divide(c,a,size,group==7))return RYZ_VM_ARITHMETIC_ERROR;
        }
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
        if(locked && op2!=0xc0 && op2!=0xc1 && op2!=0xb0 && op2!=0xb1)return RYZ_VM_OPCODE_UNSUPPORTED;
        if(op2==5){ if(c->fault)return RYZ_VM_MAP_ERROR; rv=guest_syscall(c); if(rv!=RYZ_VM_OK)return rv; }
        else if(op2==0x1e && c->repeat){if(fetch(c,1)!=0xfa)return RYZ_VM_OPCODE_UNSUPPORTED;}
        else if(op2>=0x80 && op2<=0x8f){ v=(uint64_t)(int64_t)(int32_t)fetch(c,4); target=c->cur+v; jump=condition(c,op2); }
        else if(op2>=0xc8 && op2<=0xcf){
            if(size==2)return RYZ_VM_OPCODE_UNSUPPORTED;
            rr=regop(c,(op2-0xc8)+((c->rex&1)?8:0),size);a=get(c,rr,size);v=0;
            for(n=0;n<size;n++){v=(v<<8)|(a&255);a>>=8;}
            put(c,rr,size,v);
        }
        else if(op2==0xc0 || op2==0xc1){
            if(op2==0xc0)size=1;
            rm=decode(c,&reg,&group,size);rr=regop(c,reg,size);
            if(locked && rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED;
            if(rm.reg<0 && !ryz_memory_access(c->m,address(c,rm)+c->segment,size,RYZ_READ|RYZ_WRITE))return RYZ_VM_MAP_ERROR;
            a=get(c,rm,size);b=get(c,rr,size);
            if(!c->fault){v=arithmetic(c,0,a,b,size);put(c,rr,size,a);put(c,rm,size,v);}
        }
        else if(op2==0xb0 || op2==0xb1){
            if(op2==0xb0)size=1;
            rm=decode(c,&reg,&group,size);
            if(locked && rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED;
            if(rm.reg<0 && !ryz_memory_access(c->m,address(c,rm)+c->segment,size,RYZ_WRITE))return RYZ_VM_MAP_ERROR;
            a=get(c,regop(c,0,size),size);b=get(c,rm,size);
            if(!c->fault){
                arithmetic(c,7,a,b,size);
                if(a==b)put(c,rm,size,get(c,regop(c,reg,size),size));
                else put(c,regop(c,0,size),size,b);
            }
        }
        else if((op2==0x6e || op2==0x7e) && c->operand16 && !c->repeat){
            n=(c->rex&8)?8:4;rm=decode(c,&reg,&group,n);
            if(op2==0x6e){v=get(c,rm,n);if(!c->fault){memset(c->xmm[reg],0,16);for(count=0;count<n;count++)c->xmm[reg][count]=(unsigned char)(v>>(count*8));}}
            else{v=0;for(count=0;count<n;count++)v|=(uint64_t)c->xmm[reg][count]<<(count*8);put(c,rm,n,v);}
        }
        else if((op2==0xd6 && c->operand16 && !c->repeat) || (op2==0x7e && c->repeat==0xf3)){
            unsigned char bytes[8];
            rm=decode(c,&reg,&group,8);
            if(op2==0xd6){
                memcpy(bytes,c->xmm[reg],8);
                if(rm.reg>=0){memset(c->xmm[rm.reg],0,16);memcpy(c->xmm[rm.reg],bytes,8);}
                else{v=0;for(count=0;count<8;count++)v|=(uint64_t)bytes[count]<<(count*8);put(c,rm,8,v);}
            }else{
                if(rm.reg>=0)memcpy(bytes,c->xmm[rm.reg],8);
                else{v=get(c,rm,8);for(count=0;count<8;count++)bytes[count]=(unsigned char)(v>>(count*8));}
                if(!c->fault){memset(c->xmm[reg],0,16);memcpy(c->xmm[reg],bytes,8);}
            }
        }
        else if((op2==0x6f || op2==0x7f) && (c->operand16 || c->repeat==0xf3)){
            rm=decode(c,&reg,&group,16);
            if(c->operand16 && rm.reg<0 && ((address(c,rm)+c->segment)&15))return RYZ_VM_MAP_ERROR;
            vector_move(c,rm,reg,op2==0x7f);
        }
        else if(op2==0x5e && c->repeat==0xf3 && !c->operand16){
            /* F3 0F 5E /r DIVSS xmm, xmm/m32; upper XMM & flags unchanged. */
            uint32_t a=0,b=0,q;unsigned int k;
            rm=decode(c,&reg,&group,4);
            if(c->fault)return RYZ_VM_MAP_ERROR;
            for(k=0;k<4;k++)a|=(uint32_t)c->xmm[reg][k]<<(8U*k);
            if(rm.reg>=0){
                for(k=0;k<4;k++)b|=(uint32_t)c->xmm[rm.reg][k]<<(8U*k);
            }else{
                v=get(c,rm,4);
                if(c->fault)return RYZ_VM_MAP_ERROR;
                b=(uint32_t)v;
            }
            q=divide_binary32(a,b);
            for(k=0;k<4;k++)c->xmm[reg][k]=(unsigned char)(q>>(8U*k));
        }
        else if(op2==0x2a && c->repeat==0xf3 && !c->operand16){
            /* F3 [REX.W] 0F 2A /r CVTSI2SS xmm, r/m32|r/m64.
             * Signed conversion, default nearest ties-to-even. Preserve
             * destination XMM[127:32] exactly and leave EFLAGS unchanged. */
            unsigned int i,width=(c->rex&8U)?8U:4U;
            uint32_t scalar;
            rm=decode(c,&reg,&group,width);
            if(c->fault)return RYZ_VM_MAP_ERROR;
            v=get(c,rm,width);
            if(c->fault)return RYZ_VM_MAP_ERROR;
            scalar=convert_signed_binary32(v,width);
            for(i=0;i<4;i++)c->xmm[reg][i]=(unsigned char)(scalar>>(8U*i));
        }
        else if(op2==0x70 && c->operand16 && !c->repeat){
            /* 66 0F 70 /r ib: PSHUFD xmm, xmm/m128, imm8.
             * Each destination dword i comes from source dword
             * (imm8 >> (i*2)) & 3. Copy the source first for self-alias.
             * Like other legacy SSE2 m128 forms, memory must be aligned.
             * This instruction leaves EFLAGS unchanged. */
            unsigned char source[16],out[16];
            unsigned int shuffle,i,selector;
            uint64_t at;
            rm=decode(c,&reg,&group,16);
            shuffle=(unsigned int)fetch(c,1);
            if(c->fault)return RYZ_VM_MAP_ERROR;
            if(rm.reg>=0)memcpy(source,c->xmm[rm.reg],16);
            else{
                at=address(c,rm)+c->segment;
                if((at&15U) || !ryz_memory_access(c->m,at,16,RYZ_READ))
                    return RYZ_VM_MAP_ERROR;
                memcpy(source,c->m->bytes+(size_t)(at-c->m->base),16);
            }
            for(i=0;i<4;i++){
                selector=(shuffle>>(i*2))&3U;
                memcpy(out+i*4,source+selector*4,4);
            }
            memcpy(c->xmm[reg],out,16);
        }
        else if(op2==0x62 && c->operand16 && !c->repeat){
            /* 66 0F 62 /r PUNPCKLDQ xmm, xmm/m128:
             * [old dst dword0, src dword0, old dst dword1, src dword1].
             * Copy both inputs before writing, including xmmN,xmmN alias.
             * Legacy SSE2 memory operands must be 16-byte aligned.
             * EFLAGS are unaffected; unsupported prefix forms still deny. */
            unsigned char dst[8],src[8],out[16];
            uint64_t at;
            rm=decode(c,&reg,&group,16);
            if(c->fault)return RYZ_VM_MAP_ERROR;
            memcpy(dst,c->xmm[reg],8);
            if(rm.reg>=0)memcpy(src,c->xmm[rm.reg],8);
            else{
                at=address(c,rm)+c->segment;
                if((at&15U) || !ryz_memory_access(c->m,at,16,RYZ_READ))
                    return RYZ_VM_MAP_ERROR;
                memcpy(src,c->m->bytes+(size_t)(at-c->m->base),8);
            }
            memcpy(out,dst,4);
            memcpy(out+4,src,4);
            memcpy(out+8,dst+4,4);
            memcpy(out+12,src+4,4);
            memcpy(c->xmm[reg],out,16);
        }
        else if(op2==0x6c && c->operand16 && !c->repeat){
            unsigned char bytes[8];rm=decode(c,&reg,&group,16);
            if(rm.reg>=0)memcpy(bytes,c->xmm[rm.reg],8);
            else{v=load(c,address(c,rm)+c->segment,8,RYZ_READ);for(count=0;count<8;count++)bytes[count]=(unsigned char)(v>>(count*8));}
            if(!c->fault)memcpy(c->xmm[reg]+8,bytes,8);
        }
        else if((op2==0x16 || op2==0x17) && !c->operand16 && !c->repeat){
            /* 0F 16 /r: MOVHPS from memory, MOVLHPS from XMM register.
             * 0F 17 /r: MOVHPS store to memory only (reg form invalid).
             * Low half of the destination XMM is unchanged. */
            rm=decode(c,&reg,&group,8);
            if(op2==0x16){
                if(rm.reg>=0)memcpy(c->xmm[reg]+8,c->xmm[rm.reg],8);
                else{
                    v=get(c,rm,8);
                    if(!c->fault)for(count=0;count<8;count++)
                        c->xmm[reg][8+count]=(unsigned char)(v>>(count*8));
                }
            }else{
                if(rm.reg>=0)return RYZ_VM_OPCODE_UNSUPPORTED;
                v=0;
                for(count=0;count<8;count++)v|=(uint64_t)c->xmm[reg][8+count]<<(count*8);
                store(c,address(c,rm)+c->segment,8,v);
            }
        }
        else if(op2==0x73 && c->operand16 && !c->repeat){
            /* 66 0F 73 /3 ib PSRLDQ, /7 ib PSLLDQ, register-only.
             * Shift is in bytes; counts >=16 produce all zero bytes. */
            unsigned char previous[16],shifted[16];
            unsigned int i,amount;
            rm=decode(c,&reg,&group,16);
            if(rm.reg<0 || (group!=3 && group!=7))return RYZ_VM_OPCODE_UNSUPPORTED;
            amount=(unsigned int)fetch(c,1);
            if(c->fault)return RYZ_VM_MAP_ERROR;
            memcpy(previous,c->xmm[rm.reg],16);
            for(i=0;i<16;i++){
                shifted[i]=(unsigned char)(amount>=16?0:
                    (group==3?(i+amount<16?previous[i+amount]:0):
                     (i>=amount?previous[i-amount]:0)));
            }
            memcpy(c->xmm[rm.reg],shifted,16);
        }
        else if(op2==0xeb && c->operand16 && !c->repeat){
            /* 66 0F EB /r POR xmm, xmm/m128, no EFLAGS changes. */
            rm=decode(c,&reg,&group,16);
            vector_or(c,rm,reg);
        }
        else if(op2==0xef || op2==0x57){
            if((op2==0xef && size!=2) || c->repeat)return RYZ_VM_OPCODE_UNSUPPORTED;
            rm=decode(c,&reg,&group,16);vector_xor(c,rm,reg);
        }
        else if(op2==0x10 || op2==0x11 || op2==0x28 || op2==0x29){
            if(c->repeat)return RYZ_VM_OPCODE_UNSUPPORTED;
            rm=decode(c,&reg,&group,16);
            if((op2==0x28 || op2==0x29) && rm.reg<0 && ((address(c,rm)+c->segment)&15))return RYZ_VM_MAP_ERROR;
            vector_move(c,rm,reg,(op2&1)!=0);
        }
        else if(op2==0xa3 || op2==0xab || op2==0xb3 || op2==0xbb || op2==0xba){
            int64_t index, word, remainder;
            rm=decode(c,&reg,&group,size);
            if(op2==0xba){
                if(group<4)return RYZ_VM_OPCODE_UNSUPPORTED;
                b=fetch(c,1);type=group-4;
            }else{
                b=c->r[reg]&mask(size);type=op2==0xa3?0:(op2==0xab?1:(op2==0xb3?2:3));
                if(rm.reg<0){
                    index=size==8?(int64_t)b:(size==4?(int64_t)(int32_t)b:(int64_t)(int16_t)b);
                    word=index/(int64_t)(size*8);remainder=index%(int64_t)(size*8);
                    if(remainder<0){word--;remainder+=size*8;}
                    rm.address+=(uint64_t)(word*(int64_t)size);b=(uint64_t)remainder;
                }
            }
            b%=size*8;a=get(c,rm,size);
            if(!c->fault){
                c->flags=(c->flags&~(uint64_t)CF)|((a>>b)&1);
                if(type){v=type==1?a|(UINT64_C(1)<<b):(type==2?a&~(UINT64_C(1)<<b):a^(UINT64_C(1)<<b));put(c,rm,size,v);}
            }
        }
        else if(op2==0xbc || op2==0xbd){
            if(c->repeat)return RYZ_VM_OPCODE_UNSUPPORTED;
            rm=decode(c,&reg,&group,size);v=get(c,rm,size);
            if(!c->fault){
                c->flags=(c->flags & ~UINT64_C(64))|(v==0?64:0);
                if(v){
                    n=op2==0xbc?0:size*8-1;
                    if(op2==0xbc){while(((v>>n)&1)==0)n++;}
                    else{while(((v>>n)&1)==0)n--;}
                    put(c,regop(c,reg,size),size,n);
                }
            }
        }
        else if(op2==0xaf){
            rm=decode(c,&reg,&group,size);rr=regop(c,reg,size);
            a=get(c,rr,size);b=get(c,rm,size);
            if(!c->fault)put(c,rr,size,multiply(c,a,b,size));
        }
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
void ryz_cpu_init(RyzCpu *c,RyzLinuxProcess *p,RyzLinuxMemory *m,uint64_t entry,uint64_t stack,RyzVmResult *result)
{
    memset(c,0,sizeof(*c));c->p=p;c->m=m;c->ip=entry;c->r[4]=stack;c->flags=0x202;c->result=result;
}
int ryz_cpu_tick(RyzCpu *c)
{
    int rv;
    if(c->result->executed_steps>=cpu_limit(c))return RYZ_VM_STEP_LIMIT;
    ryz_memory_commit(c->m,1);c->m->bus_valid=0;
    c->result->last_rip=c->ip;c->result->executed_steps++;c->extra_steps=0;
    rv=step(c);if(rv==RYZ_CPU_MOVED)return rv;
    ryz_memory_commit(c->m,1);
    c->result->executed_steps+=c->extra_steps;return rv;
}
int ryz_cpu_run(RyzLinuxProcess *p,RyzLinuxMemory *m,uint64_t entry,uint64_t stack,RyzVmResult *result)
{
    RyzCpu c;int rv;
    ryz_cpu_init(&c,p,m,entry,stack,result);
    for(;;){
        rv=ryz_cpu_tick(&c);if(rv!=RYZ_VM_OK)return rv;
        if(p->exited){if(c.tid_address && ryz_memory_access(m,c.tid_address,4,RYZ_WRITE))store(&c,c.tid_address,4,0);
            result->exited=1;result->exit_status=p->exit_status;return RYZ_VM_OK;}
    }
}
