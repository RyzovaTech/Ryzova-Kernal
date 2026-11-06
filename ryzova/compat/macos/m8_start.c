/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../windows/runtime.h"
#include "m8_start.h"

#ifndef CW_PLAN9
#include <string.h>
#endif

enum {
    Intel64 = 0x01000007, Arm64 = 0x0100000c,
    StackBase = 0x400000, StackBytes = Mac8StackBytes, StartBudget = 4096,
    Argv = 0x100, Envp = 0x118, Program = 0x130, Version = 0x140, GuardOffset = 8, StreamsOffset = 16, ErrnoOffset = 16
};

typedef unsigned long long Word;
#define SERVICE_BASE (MAC8_BASE+Mac8Limit)
#define HEAP_BASE (SERVICE_BASE+Mac8ServiceBytes)
#define WRITABLE_BASE (HEAP_BASE+Mac8HeapBytes)
enum { ServiceExtent = Mac8ArenaBytes-Mac8StackBytes };
#define STREAM_HANDLE 0x18000ULL
#define ERRNO_ADDRESS (WRITABLE_BASE+ErrnoOffset)

static Word
read_le(const unsigned char *data, unsigned int bytes)
{
    Word value = 0;
    unsigned int i;
    for(i=0; i<bytes; i++)
        value |= (Word)data[i] << (8*i);
    return value;
}

static void
write_le(unsigned char *data, unsigned int bytes, Word value)
{
    unsigned int i;
    for(i=0; i<bytes; i++)
        data[i] = value >> (8*i);
}

static Word
sign_extend(unsigned int value, unsigned int bits)
{
    Word range = (Word)1 << bits;
    return (Word)value - ((value & (range>>1)) ? range : 0);
}

static int
stack_span(Word addr, unsigned int count)
{
    return count <= StackBytes && addr >= StackBase && addr-StackBase <= StackBytes-count;
}

static const unsigned char *
guest_read(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
           Word at, unsigned int bytes, int services)
{
    if(mac8_access(plan, at, bytes, Mac8Read))
        return arena+(at-MAC8_BASE);
    if(stack_span(at, bytes))
        return stack+(at-StackBase);
    if(services && at>=SERVICE_BASE && bytes<=Mac8ServiceBytes+Mac8HeapBytes+Mac8WritableBytes &&
       at-SERVICE_BASE<=Mac8ServiceBytes+Mac8HeapBytes+Mac8WritableBytes-bytes)
        return arena+(at-MAC8_BASE);
    return 0;
}

static unsigned char *
guest_write(const Mac8Image *plan, unsigned char *arena, unsigned char *stack,
            Word at, unsigned int bytes, int services)
{
    if(mac8_access(plan, at, bytes, Mac8Write))
        return arena+(at-MAC8_BASE);
    if(stack_span(at, bytes))
        return stack+(at-StackBase);
    if(services && at>=HEAP_BASE && bytes<=Mac8HeapBytes+Mac8WritableBytes &&
       at-HEAP_BASE<=Mac8HeapBytes+Mac8WritableBytes-bytes)
        return arena+(at-MAC8_BASE);
    return 0;
}

static Word
resolve_data(const char *name)
{
    static const char *streams[] = {"___stdinp", "___stdoutp", "___stderrp"};
    unsigned int i;
    if(!strcmp(name, "___stack_chk_guard"))
        return SERVICE_BASE+GuardOffset;
    for(i=0; i<3; i++)
        if(!strcmp(name, streams[i]))
            return SERVICE_BASE+StreamsOffset+8*i;
    return 0;
}

/* The only configured locale is C, including the default selected by
 * an empty string. A null pointer queries the current locale. */
static int
locale_call(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
            Word category, Word locale)
{
    const unsigned char *p;
    if((unsigned int)category!=0)
        return 0;
    if(!locale)
        return 1;
    p = guest_read(plan, arena, stack, locale, 1, 1);
    if(!p)
        return 0;
    if(!p[0])
        return 1;
    p = guest_read(plan, arena, stack, locale, 2, 1);
    return p && p[0]=='C' && p[1]==0;
}

static int
print_string(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
             Word format, Word string, int stack_argument, Mac8Stop *out)
{
    unsigned char buf[Mac8OutputLimit];
    const unsigned char *p;
    unsigned int i, count = 0, room = Mac8OutputLimit-out->stdout_bytes;
    int used = 0;
    for(i=0; i<=Mac8OutputLimit; i++){
        p = guest_read(plan, arena, stack, format+i, 1, 1);
        if(!p)
            return -1;
        if(!*p){
            memcpy(out->stdout_data+out->stdout_bytes, buf, count);
            out->stdout_bytes += count;
            return count;
        }
        if(*p=='%'){
            p = guest_read(plan, arena, stack, format+(++i), 1, 1);
            if(!p)
                return -1;
            if(*p=='s'){
                if(used)
                    return -1;
                used = 1;
                if(stack_argument){
                    p = guest_read(plan, arena, stack, string, 8, 1);
                    if(!p)
                        return -1;
                    string = read_le(p, 8);
                }
                for(;; string++){
                    p = guest_read(plan, arena, stack, string, 1, 1);
                    if(!p)
                        return -1;
                    if(!*p)
                        break;
                    if(count==room)
                        return -1;
                    buf[count++] = *p;
                }
                continue;
            }
            if(*p!='%')
                return -1;
        }
        if(count==room)
            return -1;
        buf[count++] = *p;
    }
    return -1;
}

/* Return 1 for a supported call, 0 for an unknown contract, and -1 for
 * a guest memory or allocation-ownership fault. Return 2 for guest exit. */
static int
service_call(const Mac8Image *plan, unsigned char *arena, unsigned char *stack,
             Mac8Heap *heap, const char *name, Word a0, Word a1, Word varargs,
             Word *result, unsigned int *closed, Mac8Stop *out)
{
    unsigned int offset, i;
    const unsigned char *left, *right;
    int count, zero = !strcmp(name, "_calloc");
    *result = 0;
    if(!strcmp(name, "_setlocale")){
        if(!locale_call(plan, arena, stack, a0, a1))
            return -1;
        *result = SERVICE_BASE;
        out->locale_calls++;
    }else if(!strcmp(name, "___error")){
        *result = ERRNO_ADDRESS;
    }else if(!strcmp(name, "_malloc") || zero){
        Word bytes = a0;
        if(zero)
            bytes = a1 && a0>Mac8HeapBytes/a1 ? Mac8HeapBytes+1 : a0*a1;
        offset = mac8_alloc(heap, bytes);
        if(offset!=Mac8HeapBytes){
            if(zero && bytes)
                memset(arena+(HEAP_BASE-MAC8_BASE)+offset, 0, bytes);
            *result = HEAP_BASE+offset;
        }else
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 12); /* ENOMEM */
        out->alloc_calls++;
    }else if(!strcmp(name, "_strcmp")){
        for(i=0; i<65536; i++){
            left = guest_read(plan, arena, stack, a0+i, 1, 1);
            right = guest_read(plan, arena, stack, a1+i, 1, 1);
            if(!left || !right)
                return -1;
            if(*left!=*right || !*left){
                *result = (unsigned int)((int)*left-(int)*right);
                return 1;
            }
        }
        return -1;
    }else if(!strcmp(name, "_printf")){
        if(*closed&2)
            return -1;
        count = print_string(plan, arena, stack, a0, varargs ? varargs : a1, varargs!=0, out);
        if(count<0)
            return -1;
        *result = count;
    }else if(!strcmp(name, "_ferror") || !strcmp(name, "_fflush") || !strcmp(name, "_fclose")){
        if(a0==0 && !strcmp(name, "_fflush"))
            return 1;
        if(a0<STREAM_HANDLE || a0>STREAM_HANDLE+32 || (a0-STREAM_HANDLE)%16)
            return -1;
        i = 1U<<((a0-STREAM_HANDLE)/16);
        if(*closed&i)
            return -1;
        if(!strcmp(name, "_fclose"))
            *closed |= i;
    }else if(!strcmp(name, "_exit")){
        out->exit_code = a0&255;
        return 2;
    }else if(!strcmp(name, "_free")){
        if(a0 && (a0<HEAP_BASE || a0-HEAP_BASE>=Mac8HeapBytes ||
                  !mac8_free(heap, a0-HEAP_BASE)))
            return -1;
    }else
        return 0;
    return 1;
}

static int
stop_at_import(const Mac8Image *plan, Mac8Stop *out, Word target, Word a0, Word a1)
{
    Word delta;
    if(target < MAC8_UNRESOLVED)
        return 0;
    delta = target-MAC8_UNRESOLVED;
    if(delta%16 || delta/16 >= plan->imports)
        return 0;
    out->pc = target;
    out->arg0 = a0;
    out->arg1 = a1;
    out->name = plan->names[delta/16];
    return 1;
}

static int
intel_start(const Mac8Image *plan, const unsigned char *image, unsigned char *arena,
            unsigned char *stack, int services, Mac8Stop *out)
{
    CwMachine machine;
    Mac8Heap heap = {0};
    unsigned int i, closed = 0;
    int handled;
    Word result;
    memset(&machine, 0, sizeof(machine));
    machine.image = arena;
    machine.stack = stack;
    machine.stack_base = StackBase;
    machine.plan.base = MAC8_BASE;
    machine.plan.image_bytes = plan->mapped_bytes;
    machine.plan.count = Mac8Segments-1;
    for(i=1; i<Mac8Segments; i++){
        machine.plan.sections[i-1].rva = plan->segments[i].offset;
        machine.plan.sections[i-1].size = plan->segments[i].bytes;
        machine.plan.sections[i-1].permissions = plan->segments[i].protection;
    }
    if(services){
        machine.plan.image_bytes = ServiceExtent;
        i = machine.plan.count++;
        machine.plan.sections[i].rva = Mac8Limit;
        machine.plan.sections[i].size = Mac8ServiceBytes;
        machine.plan.sections[i].permissions = Mac8Read;
        i = machine.plan.count++;
        machine.plan.sections[i].rva = HEAP_BASE-MAC8_BASE;
        machine.plan.sections[i].size = Mac8HeapBytes+Mac8WritableBytes;
        machine.plan.sections[i].permissions = Mac8Read|Mac8Write;
    }
    machine.ip = MAC8_BASE+plan->entry;
    machine.r[4] = StackBase+StackBytes-8;
    machine.r[7] = 2; /* argc in RDI */
    machine.r[6] = StackBase+Argv;
    machine.r[2] = StackBase+Envp;
    machine.r[1] = StackBase+Envp+8;
    for(out->steps=0; out->steps<StartBudget; out->steps++){
        if(stop_at_import(plan, out, machine.ip, machine.r[7], machine.r[6])){
            Word sp = machine.r[4], link;
            if(!services)
                return 1;
            if(sp%16!=8 || !stack_span(sp, 8))
                return 0;
            link = read_le(stack+(sp-StackBase), 8);
            if(!mac8_access(plan, link, 1, Mac8Execute))
                return 0;
            handled = service_call(plan, arena, stack, &heap, (const char *)image+out->name,
                                   out->arg0, out->arg1, 0, &result, &closed, out);
            if(handled!=1)
                return handled<0 ? 0 : handled==0 ? 1 : 2;
            machine.r[4] += 8;
            machine.r[0] = result;
            machine.ip = link;
            out->pc = out->name = 0;
            continue;
        }
        out->last_pc = machine.ip;
        if(cw_cpu_step(&machine) != CW_OK)
            return 0;
    }
    return 0;
}

static unsigned int
arm_flags(Word a, Word b, Word value, int wide, int subtract)
{
    Word mask = wide ? ~(Word)0 : 0xffffffffU;
    Word sign = (mask>>1)+1;
    a &= mask;
    b &= mask;
    value &= mask;
    return ((value&sign)!=0)*8 + (!value)*4 +
           (subtract ? a>=b : value<a)*2 +
           (((a^value)&(subtract ? a^b : ~(a^b))&sign)!=0);
}

static int
arm_cond(unsigned int flags, unsigned int cond)
{
    int n = (flags&8)!=0, z = (flags&4)!=0, c = (flags&2)!=0, v = (flags&1)!=0;
    int yes;
    switch(cond>>1){
    case 0: yes=z; break;
    case 1: yes=c; break;
    case 2: yes=n; break;
    case 3: yes=v; break;
    case 4: yes=c && !z; break;
    case 5: yes=n==v; break;
    case 6: yes=n==v && !z; break;
    default: return 1;
    }
    return yes!=(int)(cond&1);
}

static int
arm_bitmask(unsigned int op, Word *out)
{
    unsigned int tag = ((op>>16)&64) | ((~op>>10)&63);
    unsigned int len = 0, size, ones, rotate, i, width = (op>>31) ? 64 : 32;
    Word elem, mask;
    while(tag>>1){
        len++;
        tag >>= 1;
    }
    size = 1U<<len;
    ones = (op>>10)&(size-1);
    rotate = (op>>16)&(size-1);
    if(!len || size>width || ones==size-1)
        return 0;
    mask = size==64 ? ~(Word)0 : ((Word)1<<size)-1;
    elem = ((Word)1<<(ones+1))-1;
    if(rotate)
        elem = ((elem>>rotate)|(elem<<(size-rotate)))&mask;
    *out = 0;
    for(i=0; i<width; i+=size)
        *out |= elem<<i;
    return 1;
}

static int
arm_start(const Mac8Image *plan, const unsigned char *image, unsigned char *arena,
          unsigned char *stack, int services, Mac8Stop *out)
{
    Word r[31] = {0}, sp = StackBase+StackBytes, result;
    Mac8Heap heap = {0};
    unsigned char fp[32][16] = {{0}};
    Word pc = MAC8_BASE+plan->entry, next, addr, v, imm;
    unsigned int op, rd, rn, rt2, bytes, mode, cond, closed = 0;
    Word access;
    unsigned int flags = 0;
    int handled, wide, sub;
    const unsigned char *p;
    unsigned char *dst;
    r[0] = 2;
    r[1] = StackBase+Argv;
    r[2] = StackBase+Envp;
    r[3] = StackBase+Envp+8;
    for(out->steps=0; out->steps<StartBudget; out->steps++){
        if(stop_at_import(plan, out, pc, r[0], r[1])){
            if(!services)
                return 1;
            if(sp%16 || r[30]%4 || !mac8_access(plan, r[30], 4, Mac8Execute))
                return 0;
            handled = service_call(plan, arena, stack, &heap, (const char *)image+out->name,
                                   out->arg0, out->arg1, sp, &result, &closed, out);
            if(handled!=1)
                return handled<0 ? 0 : handled==0 ? 1 : 2;
            r[0] = result;
            pc = r[30];
            out->pc = out->name = 0;
            continue;
        }
        out->last_pc = pc;
        if(pc%4 || !mac8_access(plan, pc, 4, Mac8Execute))
            return 0;
        op = read_le(arena+(pc-MAC8_BASE), 4);
        next = pc+4;
        rd = op&31;
        rn = (op>>5)&31;
        v = rn==31 ? sp : r[rn];
        imm = (op>>10)&0xfff;
        if((op&0x1f800000U)==0x11000000U){ /* ADD/SUB (immediate) */
            if(op&(1U<<22))
                imm <<= 12;
            wide = op>>31;
            sub = (op>>30)&1;
            addr = sub ? v-imm : v+imm;
            if(!wide)
                addr = (unsigned int)addr;
            if(op&(1U<<29))
                flags = arm_flags(v, imm, addr, wide, sub);
            if(rd!=31)
                r[rd] = addr;
            else if(!(op&(1U<<29))){
                if(addr%16 || !stack_span(addr, 0))
                    return 0;
                sp = addr;
            }
        }else if((op&0x1f200000U)==0x0b000000U){ /* ADD/SUB (shifted register) */
            mode = (op>>22)&3;
            bytes = (op>>10)&63;
            wide = op>>31;
            sub = (op>>30)&1;
            rt2 = (op>>16)&31;
            if(mode==3 || (!wide && bytes>=32))
                return 0;
            access = rt2==31 ? 0 : r[rt2];
            if(!wide)
                access = (unsigned int)access;
            if(mode==0)
                access <<= bytes;
            else if(mode==1)
                access >>= bytes;
            else if(bytes){
                if(!wide)
                    access = sign_extend((unsigned int)access, 32);
                access = (access>>bytes) | ((access>>63) ? ~(~(Word)0>>bytes) : 0);
            }
            v = rn==31 ? 0 : r[rn];
            addr = sub ? v-access : v+access;
            if(op&(1U<<29))
                flags = arm_flags(v, access, addr, wide, sub);
            if(rd!=31)
                r[rd] = wide ? addr : (unsigned int)addr;
        }else if((op&0x7e000000U)==0x28000000U && (mode=(op>>23)&3)!=0){ /* STP/LDP W/X */
            bytes = (op>>31) ? 8 : 4;
            rt2 = (op>>10)&31;
            addr = v+sign_extend((op>>15)&0x7f, 7)*bytes;
            access = mode==1 ? v : addr;
            if(mode!=2 && rn!=31 && (rn==rd || rn==rt2))
                return 0;
            if(mode!=2 && rn==31 && (addr%16 || !stack_span(addr, 0)))
                return 0;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, access, 2*bytes, services);
                if(!p || rd==rt2)
                    return 0;
                if(rd!=31)
                    r[rd] = read_le(p, bytes);
                if(rt2!=31)
                    r[rt2] = read_le(p+bytes, bytes);
            }else{
                dst = guest_write(plan, arena, stack, access, 2*bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
                write_le(dst+bytes, bytes, rt2==31 ? 0 : r[rt2]);
            }
            if(mode!=2){
                if(rn==31)
                    sp = addr;
                else
                    r[rn] = addr;
            }
        }else if((op&0x3fa00000U)==0x38000000U && (mode=(op>>10)&3)!=2){ /* LDUR/STUR or indexed */
            bytes = 1U<<(op>>30);
            addr = v+sign_extend((op>>12)&0x1ff, 9);
            access = mode==1 ? v : addr;
            if(mode && ((rn!=31 && rd==rn) ||
                        (rn==31 && (addr%16 || !stack_span(addr, 0)))))
                return 0;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, access, bytes, services);
                if(!p)
                    return 0;
                if(rd!=31)
                    r[rd] = read_le(p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, access, bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
            }
            if(mode){
                if(rn==31)
                    sp = addr;
                else
                    r[rn] = addr;
            }
        }else if((op&0x1f200000U)==0x0a000000U && !(op&0x00c0fc00U)){ /* Logical, unshifted */
            rt2 = (op>>16)&31;
            v = rn==31 ? 0 : r[rn];
            access = rt2==31 ? 0 : r[rt2];
            mode = (op>>29)&3;
            if(mode==1)
                v |= access;
            else if(mode==2)
                v ^= access;
            else
                v &= access;
            if(!(op>>31))
                v = (unsigned int)v;
            if(mode==3)
                flags = ((v>>(op>>31 ? 63 : 31))!=0)*8 + (!v)*4;
            if(rd!=31)
                r[rd] = v;
        }else if((op&0x1f000000U)==0x10000000U && rd!=31){ /* ADR/ADRP */
            imm = (((op>>5)&0x7ffff)<<2) | ((op>>29)&3);
            access = sign_extend(imm, 21);
            r[rd] = op>>31 ? (pc&~(Word)4095)+(access<<12) : pc+access;
        }else if((op&0x1f800000U)==0x12800000U){ /* MOVN/MOVZ/MOVK */
            mode = (op>>29)&3;
            bytes = ((op>>21)&3)*16;
            if(mode==1 || (!(op>>31) && bytes>=32))
                return 0;
            v = (Word)((op>>5)&0xffff)<<bytes;
            if(mode==0)
                v = ~v;
            if(mode==3 && rd!=31)
                v |= r[rd]&~((Word)0xffff<<bytes);
            if(rd!=31)
                r[rd] = op>>31 ? v : (unsigned int)v;
        }else if((op&0x3fa00c00U)==0x38200800U){ /* LDR/STR, register offset */
            rt2 = (op>>16)&31;
            mode = (op>>13)&7;
            bytes = 1U<<(op>>30);
            access = rt2==31 ? 0 : r[rt2];
            if(mode==2)
                access = (unsigned int)access;
            else if(mode==6)
                access = sign_extend((unsigned int)access, 32);
            else if(mode!=3 && mode!=7)
                return 0;
            if(op&(1U<<12))
                access *= bytes;
            addr = v+access;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                if(rd!=31)
                    r[rd] = read_le(p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
            }
        }else if((op&0x7f800000U)==0x53000000U){ /* UBFM and its shift aliases */
            unsigned int first = (op>>16)&63, last = (op>>10)&63;
            wide = op>>31;
            bytes = wide ? 64 : 32;
            if(((op>>22)&1)!=(unsigned int)wide || first>=bytes || last>=bytes)
                return 0;
            v = rn==31 ? 0 : r[rn];
            if(!wide)
                v = (unsigned int)v;
            if(last>=first){
                mode = last-first+1;
                v >>= first;
                if(mode<64)
                    v &= ((Word)1<<mode)-1;
            }else
                v = (v&(((Word)1<<(last+1))-1))<<(bytes-first);
            if(rd!=31)
                r[rd] = wide ? v : (unsigned int)v;
        }else if((op&0xfffffc00U)==0x93407c00U){ /* SXTW */
            if(rd!=31)
                r[rd] = rn==31 ? 0 : sign_extend((unsigned int)r[rn], 32);
        }else if((op&0x3f800000U)==0x39000000U){ /* LDR/STR, unsigned offset */
            bytes = 1U<<(op>>30);
            addr = v+imm*bytes;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                if(rd!=31)
                    r[rd] = read_le(p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
            }
        }else if((op&0x9ff8fc00U)==0x0f00e400U){ /* MOVI, byte or byte-mask immediate */
            imm = (((op>>16)&7)<<5) | ((op>>5)&31);
            if(op&(1U<<29)){
                for(bytes=0; bytes<8; bytes++)
                    fp[rd][bytes] = fp[rd][bytes+8] = (imm&(1U<<bytes)) ? 255 : 0;
                if(!(op&(1U<<30)))
                    memset(fp[rd]+8, 0, 8);
            }else{
                memset(fp[rd], imm, 8);
                memset(fp[rd]+8, (op&(1U<<30)) ? imm : 0, 8);
            }
        }else if((op&0xff800000U)==0xad000000U){ /* STP/LDP Q, signed offset */
            rt2 = (op>>10)&31;
            addr = v+sign_extend((op>>15)&0x7f, 7)*16;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, 32, services);
                if(!p || rd==rt2)
                    return 0;
                memcpy(fp[rd], p, 16);
                memcpy(fp[rt2], p+16, 16);
            }else{
                dst = guest_write(plan, arena, stack, addr, 32, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], 16);
                memcpy(dst+16, fp[rt2], 16);
            }
        }else if((op&0xffa00c00U)==0x3c800000U){ /* STUR/LDUR Q */
            addr = v+sign_extend((op>>12)&0x1ff, 9);
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, 16, services);
                if(!p)
                    return 0;
                memcpy(fp[rd], p, 16);
            }else{
                dst = guest_write(plan, arena, stack, addr, 16, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], 16);
            }
        }else if((op&0xff800000U)==0xfd000000U ||
                 (op&0xff800000U)==0x3d800000U){ /* LDR/STR D/Q, unsigned offset */
            bytes = (op>>31) ? 8 : 16;
            addr = v+imm*bytes;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                memset(fp[rd], 0, 16);
                memcpy(fp[rd], p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], bytes);
            }
        }else if((op&0x1f800000U)==0x12000000U){ /* AND/ORR/EOR/ANDS, immediate */
            if(!arm_bitmask(op, &access))
                return 0;
            v = rn==31 ? 0 : r[rn];
            mode = (op>>29)&3;
            if(mode==1)
                v |= access;
            else if(mode==2)
                v ^= access;
            else
                v &= access;
            if(!(op>>31))
                v = (unsigned int)v;
            if(mode==3)
                flags = ((v>>(op>>31 ? 63 : 31))!=0)*8 + (!v)*4;
            if(rd!=31)
                r[rd] = v;
            else if(mode!=3)
                return 0;
        }else if((op&0x3fe00800U)==0x1a800000U){ /* CSEL/CSINC */
            rt2 = (op>>16)&31;
            if(arm_cond(flags, (op>>12)&15))
                v = rn==31 ? 0 : r[rn];
            else
                v = (rt2==31 ? 0 : r[rt2])+((op>>10)&1);
            if(rd!=31)
                r[rd] = op>>31 ? v : (unsigned int)v;
        }else if((op&0xff000010U)==0x54000000U){ /* B.cond */
            cond = op&15;
            if(arm_cond(flags, cond))
                next = pc+(sign_extend((op>>5)&0x7ffff, 19)<<2);
        }else if((op&0x7e000000U)==0x36000000U){ /* TBZ/TBNZ */
            v = rd==31 ? 0 : r[rd];
            mode = ((op>>26)&32) | ((op>>19)&31);
            if(((v>>mode)&1)==((op>>24)&1))
                next = pc+(sign_extend((op>>5)&0x3fff, 14)<<2);
        }else if((op&0x7e000000U)==0x34000000U){ /* CBZ/CBNZ */
            v = rd==31 ? 0 : r[rd];
            if(!(op>>31))
                v = (unsigned int)v;
            if((v!=0)==((op>>24)&1))
                next = pc+(sign_extend((op>>5)&0x7ffff, 19)<<2);
        }else if((op&0x7c000000U)==0x14000000U){ /* B/BL */
            if(op>>31)
                r[30] = next;
            next = pc+(sign_extend(op&0x03ffffffU, 26)<<2);
        }else if(((op&0xfffffc1fU)==0xd61f0000U || (op&0xfffffc1fU)==0xd65f0000U)
                 && rn!=31){ /* BR/RET */
            next = r[rn];
        }else
            return 0;
        pc = next;
    }
    return 0;
}

int
mac8_start(const unsigned char *image, unsigned int length, unsigned char *arena,
           unsigned int capacity, Word guard, Mac8Stop *out)
{
    Mac8Image plan;
    unsigned char *stack;
    unsigned int image_capacity, i;
    if(!out || !arena || capacity<StackBytes)
        return 0;
    image_capacity = capacity-StackBytes;
    if(guard && image_capacity<ServiceExtent)
        return 0;
    if(!mac8_load_bound(image, length, arena, image_capacity, &plan, guard ? resolve_data : 0))
        return 0;
    if(guard){
        memset(arena+Mac8Limit, 0, ServiceExtent-Mac8Limit);
        arena[Mac8Limit] = 'C';
        write_le(arena+Mac8Limit+GuardOffset, 8, guard);
        for(i=0; i<3; i++)
            write_le(arena+Mac8Limit+StreamsOffset+8*i, 8, STREAM_HANDLE+16*i);
    }
    stack = arena+(guard ? ServiceExtent : plan.mapped_bytes);
    memset(stack, 0, StackBytes);
    write_le(stack+Argv, 8, StackBase+Program);
    write_le(stack+Argv+8, 8, StackBase+Version);
    memcpy(stack+Program, "jq", sizeof("jq"));
    memcpy(stack+Version, "--version", sizeof("--version"));
    memset(out, 0, sizeof(*out));
    if(plan.cpu==Intel64)
        return intel_start(&plan, image, arena, stack, guard!=0, out);
    if(plan.cpu==Arm64)
        return arm_start(&plan, image, arena, stack, guard!=0, out);
    return 0;
}
