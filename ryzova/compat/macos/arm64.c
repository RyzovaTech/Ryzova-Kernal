/* SPDX-License-Identifier: GPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#else
#include <string.h>
#endif
#include "arm64.h"
#include "dynamic.h"

typedef unsigned long long Word;
typedef unsigned int Insn;

enum { ArmStackBase = 0x400000, ArmStackSize = 4096, ArmReturn = 0x10008, ArmSteps = 64 };
static unsigned char arm_text[MacArmPage], arm_data[MacArmPage], arm_stack[ArmStackSize];

static Insn
get32(const unsigned char *p)
{
    return (Insn)p[0] | (Insn)p[1]<<8 | (Insn)p[2]<<16 | (Insn)p[3]<<24;
}

static Word
get64(const unsigned char *p)
{
    return get32(p) | (Word)get32(p+4)<<32;
}

static void
put64(unsigned char *p, Word value)
{
    unsigned int i;
    for(i=0; i<8; i++)
        p[i] = value>>(8*i);
}

static Word
sign_extend(Insn value, unsigned int bits)
{
    Word width = (Word)1<<bits;
    return (Word)value - ((value & (width>>1)) ? width : 0);
}

static int
inside(Word addr, Word start, unsigned int size, Word length)
{
    return addr>=start && addr-start<=size && length<=size-(addr-start);
}

/* A bounded A64 interpreter for this CLI profile. X0/X1/X2 carry Darwin's
 * write arguments. X30 holds the return link and SP stays 16-byte aligned. */
int
mac_arm64_run(const unsigned char *image, unsigned int length, MacArmResult *out, MacFiles *files)
{
    Word regs[31], sp, pc, next, address, stub_branch;
    Insn op, rd, rn, imm;
    unsigned int step, id, stub_id = MacImports, pair;
    int equal = 0;
    MacDynamic plan;

    memset(out, 0, sizeof(*out));
    memset(regs, 0, sizeof regs);
    memset(arm_stack, 0, sizeof arm_stack);
    if(!mac_dynamic_load(image, length, arm_text, arm_data, &plan, 1, files!=0))
        return 0;
    if(files){
        if(!mac_work_args(files, arm_stack))
            return 0;
        regs[0] = 2;
        regs[1] = ArmStackBase+WorkArgv;
        regs[2] = ArmStackBase+WorkEnvp;
    }
    pc = MacBase+plan.entry;
    sp = ArmStackBase+ArmStackSize;
    regs[30] = ArmReturn;
    stub_branch = 0;
    out->rebases = plan.rebases;

    for(step=0; step<ArmSteps; step++){
        if(pc%4 || !inside(pc, MacBase, MacArmPage, 4))
            return 0;
        op = get32(arm_text+pc-MacBase);
        next = pc+4;
        rd = op&31;
        rn = (op>>5)&31;
        if(op==0xa9bf7bfdU || (files && op==0xa9bf53f3U)){ /* stp x29, x30, [sp, #-16]! */
            if(sp<16 || !inside(sp-16, ArmStackBase, ArmStackSize, 16))
                return 0;
            sp -= 16;
            pair = op==0xa9bf7bfdU ? 29 : 19;
            put64(arm_stack+(sp-ArmStackBase), regs[pair]);
            put64(arm_stack+(sp-ArmStackBase)+8, regs[pair+1]);
        }else if(op==0xa8c17bfdU || (files && op==0xa8c153f3U)){ /* ldp x29, x30, [sp], #16 */
            if(!inside(sp, ArmStackBase, ArmStackSize, 16))
                return 0;
            pair = op==0xa8c17bfdU ? 29 : 19;
            regs[pair] = get64(arm_stack+(sp-ArmStackBase));
            regs[pair+1] = get64(arm_stack+(sp-ArmStackBase)+8);
            sp += 16;
        }else if(files && (op==0xd10043ffU || op==0x910043ffU)){
            address = op==0xd10043ffU ? sp-16 : sp+16;
            if(!inside(address, ArmStackBase, ArmStackSize, 0))
                return 0;
            sp = address;
        }else if(files && op==0x910003e1U){
            regs[1] = sp;
        }else if(files && ((op&0xffe0ffe0U)==0x2a0003e0U ||
                           (op&0xffe0ffe0U)==0xaa0003e0U)){
            rn = (op>>16)&31;
            if(rd>=31 || rn>=31)
                return 0;
            regs[rd] = op>>31 ? regs[rn] : (Insn)regs[rn];
        }else if((op&0x9f000000U)==0x90000000U && rd<31){ /* adrp */
            imm = (((op>>5)&0x7ffff)<<2) | ((op>>29)&3);
            regs[rd] = (pc&~(Word)4095) + (sign_extend(imm, 21)<<12);
        }else if((op&0xffc00000U)==0xf9400000U && rd<31 && rn<31){ /* ldr x */
            address = regs[rn] + ((op>>10)&0xfff)*8;
            if(inside(address, MacBase+MacArmPage, MacArmPage, 8)){
                regs[rd] = get64(arm_data+(address-MacBase-MacArmPage));
                if(rd==16){
                    for(id=0; id<(files ? MacImports : 1); id++)
                        if(address==MacBase+MacArmPage+plan.slots[id]){
                            stub_id = id;
                            stub_branch = next;
                            break;
                        }
                }
            }else if(files && inside(address, ArmStackBase, ArmStackSize, 8)){
                regs[rd] = get64(arm_stack+(address-ArmStackBase));
            }else
                return 0;
        }else if((op&0xffe00000U)==0x52800000U && rd<31){ /* movz w, #imm */
            regs[rd] = (op>>5)&0xffff;
        }else if((op&0xfc000000U)==0x94000000U){ /* bl */
            regs[30] = next;
            next = pc+(sign_extend(op&0x03ffffffU, 26)<<2);
        }else if(op==0xd61f0200U){ /* br x16, the selected GOT stub */
            if(pc!=stub_branch || stub_id>=MacImports ||
               regs[16]!=MacWriteThunk+16*stub_id || sp%16)
                return 0;
            if(files)
                regs[0] = mac_work_call(files, stub_id, regs[0], regs[1], regs[2], arm_stack);
            else{
                if(out->calls!=0 || regs[0]!=1 || regs[2]>MacArmOutput ||
                   !inside(regs[1], MacBase, MacArmPage, regs[2]))
                    return 0;
                out->size = regs[2];
                memmove(out->output, arm_text+(regs[1]-MacBase), out->size);
                out->calls++;
                regs[0] = out->size;
            }
            stub_branch = 0;
            next = regs[30];
        }else if(files && op==0x3100041fU){
            equal = (Insn)regs[0]==0xffffffffU;
        }else if(files && (op&0xfc000000U)==0x14000000U){
            next = pc+(sign_extend(op&0x03ffffffU, 26)<<2);
        }else if((op&0xffc003ffU)==0xf100001fU){ /* cmp x0, #imm */
            equal = regs[0]==((op>>10)&0xfff);
        }else if((op&0xff00001eU)==0x54000000U && (files || (op&1))){ /* b.ne */
            if((op&1) ? !equal : equal)
                next = pc+(sign_extend((op>>5)&0x7ffff, 19)<<2);
        }else if(op==0xd65f03c0U){ /* ret x30 */
            next = regs[30];
            if(next==ArmReturn){
                if(sp!=ArmStackBase+ArmStackSize || (!files && out->calls!=1))
                    return 0;
                out->status = regs[0];
                out->steps = step+1;
                return 1;
            }
        }else
            return 0;
        pc = next;
    }
    return 0;
}
