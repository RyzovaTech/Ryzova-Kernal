/* SPDX-License-Identifier: AGPL-3.0-only */
/* Linux x86_64 static-ELF proof, not a native Ryzova kernel executable loader. */
#include "subset_vm.h"
#include "elf64.h"
#define PF_X 1U

static uint32_t little32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 |
           (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static int instruction(const RyzElf64Plan *plan, uint64_t ip, size_t bytes)
{
    unsigned int i;
    for (i=0; i<plan->load_count; ++i) {
        const RyzElf64Segment *s=&plan->loads[i];
        if ((s->flags&PF_X) != 0 && ip>=s->address &&
            ip-s->address<=s->file_bytes &&
            bytes <= s->file_bytes-(ip-s->address))
            return 1;
    }
    return 0;
}
static int displacement(uint64_t base, int64_t delta, uint64_t *out)
{
    if (delta>=0) {
        if ((uint64_t)delta > UINT64_MAX-base)
            return 0;
        *out=base+(uint64_t)delta;
    } else {
        uint64_t magnitude=(uint64_t)(-(delta+1))+1U;
        if (base<magnitude)
            return 0;
        *out=base-magnitude;
    }
    return 1;
}
int ryz_vm_run_static_elf(const unsigned char *elf, size_t elf_size,
    unsigned char *arena, size_t arena_size,
    RyzLinuxWrite output, void *opaque, RyzVmResult *result)
{
    RyzElf64Plan plan;
    RyzLinuxProcess process;
    uint64_t regs[8]={0}; /* rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi */
    uint64_t lowest=UINT64_MAX, highest=0, ip, next;
    uint32_t step, syscall_count=0;
    unsigned int i;
    int rv;
    if (result!=NULL)
        memset(result,0,sizeof(*result));
    if (elf==NULL || arena==NULL || result==NULL || arena_size==0)
        return RYZ_VM_BAD_INPUT;
    if (ryz_elf64_plan(elf,elf_size,&plan)!=RYZ_ELF_OK)
        return RYZ_VM_BAD_INPUT;
    for (i=0;i<plan.load_count;++i) {
        if (plan.loads[i].map_start<lowest)
            lowest=plan.loads[i].map_start;
        if (plan.loads[i].map_end>highest)
            highest=plan.loads[i].map_end;
    }
    if (highest<=lowest || highest-lowest>RYZ_VM_MAX_SPAN ||
        highest-lowest>arena_size)
        return RYZ_VM_MAP_ERROR;
    memset(arena,0,(size_t)(highest-lowest));
    for (i=0;i<plan.load_count;++i) {
        const RyzElf64Segment *s=&plan.loads[i];
        uint64_t delta=s->address-lowest;
        if (delta>highest-lowest || s->memory_bytes>highest-lowest-delta ||
            ryz_elf64_materialize(elf,elf_size,s,arena+(size_t)delta,
                                  (size_t)(highest-lowest-delta))!=RYZ_ELF_OK)
            return RYZ_VM_MAP_ERROR;
    }
    if (ryz_linux_process_init(&process,1,1000,1000,1000,lowest,arena,
             (size_t)(highest-lowest),output,opaque)!=0)
        return RYZ_VM_MAP_ERROR;
    ip=plan.entry;
    for (step=0;step<RYZ_VM_MAX_STEPS;++step) {
        const unsigned char *code;
        unsigned char op;
        result->last_rip=ip;
        if (!instruction(&plan,ip,1))
            return RYZ_VM_MAP_ERROR;
        code=arena+(size_t)(ip-lowest);
        op=code[0];
        result->executed_steps=step+1;
        if (op>=0xb8 && op<=0xbf) {
            unsigned int reg=(unsigned int)(op-0xb8);
            if (!instruction(&plan,ip,5))
                return RYZ_VM_MAP_ERROR;
            regs[reg]=little32(code+1); /* x86_64 32-bit register zero extends */
            ip+=5;
        } else if (op==0x48 && instruction(&plan,ip,7) &&
                   code[1]==0x8d && code[2]==0x35) {
            uint64_t destination;
            int64_t rel=(int32_t)little32(code+3);
            if (!displacement(ip+7,rel,&destination))
                return RYZ_VM_MAP_ERROR;
            regs[6]=destination; /* lea disp32(%rip),%rsi */
            ip+=7;
        } else if (op==0x31 && instruction(&plan,ip,2) &&
                   code[1]==0xff) {
            regs[7]=0; /* xor %edi,%edi */
            ip+=2;
        } else if (op==0x90) {
            ip++;
        } else if (op==0xeb && instruction(&plan,ip,2)) {
            int64_t rel=(int8_t)code[1];
            if (!displacement(ip+2,rel,&next))
                return RYZ_VM_MAP_ERROR;
            ip=next; /* intentional bounded branch for loop-limit tests */
        } else if (op==0x0f && instruction(&plan,ip,2) && code[1]==0x05) {
            RyzLinuxRegs r={0};
            int64_t returned;
            r.rax=regs[0];r.rdi=regs[7];r.rsi=regs[6];r.rdx=regs[2];
            r.r10=0;r.r8=0;r.r9=0;
            if (r.rax!=1 && r.rax!=60 && r.rax!=231)
                return RYZ_VM_SYSCALL_UNSUPPORTED;
            returned=ryz_linux_syscall(&process,&r);
            ++syscall_count;
            result->syscall_count=syscall_count;
            regs[0]=(uint64_t)returned;
            ip+=2;
            if (returned<0)
                return RYZ_VM_SYSCALL_UNSUPPORTED;
            if (process.exited) {
                result->exited=1;
                result->exit_status=process.exit_status;
                return RYZ_VM_OK;
            }
        } else {
            return RYZ_VM_OPCODE_UNSUPPORTED;
        }
    }
    rv=RYZ_VM_STEP_LIMIT;
    return rv;
}
