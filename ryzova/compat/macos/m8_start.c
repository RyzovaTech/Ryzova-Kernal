/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../windows/runtime.h"
#include "m8_image.h"
#include "m8_start.h"

#ifndef CW_PLAN9
#include <string.h>
#endif

enum {
    Intel64 = 0x01000007, Arm64 = 0x0100000c,
    StackBase = 0x400000, StackBytes = CW_STACK, StartBudget = 4096,
    Argv = 0x100, Envp = 0x118, Program = 0x130, Version = 0x140
};

typedef unsigned long long Word;

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
write64(unsigned char *data, Word value)
{
    unsigned int i;
    for(i=0; i<8; i++)
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
intel_start(const Mac8Image *plan, unsigned char *arena, unsigned char *stack, Mac8Stop *out)
{
    CwMachine machine;
    unsigned int i;
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
    machine.ip = MAC8_BASE+plan->entry;
    machine.r[4] = StackBase+StackBytes-8;
    machine.r[7] = 2; /* argc in RDI */
    machine.r[6] = StackBase+Argv;
    machine.r[2] = StackBase+Envp;
    machine.r[1] = StackBase+Envp+8;
    for(out->steps=0; out->steps<StartBudget; out->steps++){
        if(stop_at_import(plan, out, machine.ip, machine.r[7], machine.r[6]))
            return 1;
        out->last_pc = machine.ip;
        if(cw_cpu_step(&machine) != CW_OK)
            return 0;
    }
    return 0;
}

static int
arm_start(const Mac8Image *plan, const unsigned char *arena, unsigned char *stack, Mac8Stop *out)
{
    Word r[31] = {0}, sp = StackBase+StackBytes;
    Word pc = MAC8_BASE+plan->entry, next, addr, v, imm;
    unsigned int op, rd, rn, rt2;
    r[0] = 2;
    r[1] = StackBase+Argv;
    r[2] = StackBase+Envp;
    r[3] = StackBase+Envp+8;
    for(out->steps=0; out->steps<StartBudget; out->steps++){
        if(stop_at_import(plan, out, pc, r[0], r[1]))
            return 1;
        out->last_pc = pc;
        if(pc%4 || !mac8_access(plan, pc, 4, Mac8Execute))
            return 0;
        op = read_le(arena+(pc-MAC8_BASE), 4);
        next = pc+4;
        rd = op&31;
        rn = (op>>5)&31;
        v = rn==31 ? sp : r[rn];
        imm = (op>>10)&0xfff;
        if((op&0xbf800000U)==0x91000000U){ /* ADD/SUB (immediate), 64 bit */
            if(op & (1U<<22))
                imm <<= 12;
            addr = (op & (1U<<30)) ? v-imm : v+imm;
            if(rd==31){
                if(addr%16 || !stack_span(addr, 0))
                    return 0;
                sp = addr;
            }else
                r[rd] = addr;
        }else if((op&0xffc00000U)==0xa9000000U){ /* STP, signed offset */
            rt2 = (op>>10)&31;
            addr = v + sign_extend((op>>15)&0x7f, 7)*8;
            if(!stack_span(addr, 16))
                return 0;
            write64(stack+(addr-StackBase), rd==31 ? 0 : r[rd]);
            write64(stack+(addr-StackBase)+8, rt2==31 ? 0 : r[rt2]);
        }else if((op&0xffe00c00U)==0xf8000000U){ /* STUR X */
            addr = v+sign_extend((op>>12)&0x1ff, 9);
            if(!stack_span(addr, 8))
                return 0;
            write64(stack+(addr-StackBase), rd==31 ? 0 : r[rd]);
        }else if((op&0xffe0ffe0U)==0xaa0003e0U && rd!=31){ /* MOV X (ORR alias) */
            rn = (op>>16)&31;
            r[rd] = rn==31 ? 0 : r[rn];
        }else if((op&0x9f000000U)==0x90000000U && rd!=31){ /* ADRP */
            imm = (((op>>5)&0x7ffff)<<2) | ((op>>29)&3);
            r[rd] = (pc&~(Word)4095) + (sign_extend(imm, 21)<<12);
        }else if((op&0xff800000U)==0x52800000U && !(op&(1U<<22)) && rd!=31){ /* MOVZ W */
            r[rd] = (unsigned int)(((op>>5)&0xffff) << (((op>>21)&1)*16));
        }else if((op&0xffc00000U)==0xf9400000U && rd!=31){ /* LDR X */
            addr = v+imm*8;
            if(!mac8_access(plan, addr, 8, Mac8Read))
                return 0;
            r[rd] = read_le(arena+(addr-MAC8_BASE), 8);
        }else if((op&0xfc000000U)==0x94000000U){ /* BL */
            r[30] = next;
            next = pc+(sign_extend(op&0x03ffffffU, 26)<<2);
        }else if((op&0xfffffc1fU)==0xd61f0000U && rn!=31){ /* BR */
            next = r[rn];
        }else
            return 0;
        pc = next;
    }
    return 0;
}

int
mac8_start(const unsigned char *image, unsigned int length, unsigned char *arena,
           unsigned int capacity, Mac8Stop *out)
{
    Mac8Image plan;
    unsigned char *stack;
    if(!out || !arena || capacity < StackBytes ||
       !mac8_load(image, length, arena, capacity-StackBytes, &plan))
        return 0;
    stack = arena+plan.mapped_bytes;
    memset(stack, 0, StackBytes);
    write64(stack+Argv, StackBase+Program);
    write64(stack+Argv+8, StackBase+Version);
    memcpy(stack+Program, "jq", sizeof("jq"));
    memcpy(stack+Version, "--version", sizeof("--version"));
    memset(out, 0, sizeof(*out));
    if(plan.cpu==Intel64)
        return intel_start(&plan, arena, stack, out);
    if(plan.cpu==Arm64)
        return arm_start(&plan, arena, stack, out);
    return 0;
}
