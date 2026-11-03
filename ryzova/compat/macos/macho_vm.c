/* SPDX-License-Identifier: AGPL-3.0-only */
#include "macho_vm.h"
#include "macho64.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* MAC-1 host-side only: interpret a finite AMD64 integer instruction subset
 * from synthetic, static Mach-O LC_MAIN. Never cast guest bytes to code,
 * enter an OS syscall, use host addresses as guest addresses, or map W+X. */
#define VM_READ 1U
#define VM_WRITE 2U
#define VM_EXECUTE 4U

typedef struct Region {
    uint64_t base, extent, backed;
    uint32_t permissions;
    unsigned char *buffer;
} Region;
typedef struct Machine {
    Region segments[RYZ_MACHO_MAX_SEGMENTS];
    uint32_t count;
    uint64_t rip, last;
    uint32_t eax, steps;
} Machine;

static void release_regions(Machine *machine) {
    uint32_t i;
    for(i=0;i<machine->count;++i) {
        free(machine->segments[i].buffer);
        machine->segments[i].buffer=NULL;
    }
}

/* The *entire* width must fall inside exactly one accepted virtual region. */
static unsigned char *access_region(Machine *machine,uint64_t address,
                                    size_t width,uint32_t permission,
                                    int file_backed) {
    uint32_t i;
    if(width==0)return NULL;
    for(i=0;i<machine->count;++i) {
        Region *s=&machine->segments[i];
        uint64_t relative,limit;
        if(address<s->base || (s->permissions&permission)!=permission)
            continue;
        relative=address-s->base;
        limit=file_backed?s->backed:s->extent;
        if(relative>limit || (uint64_t)width>limit-relative)
            continue;
        return s->buffer+(size_t)relative;
    }
    return NULL;
}

static int get_code_byte(Machine *machine,uint8_t *out) {
    unsigned char *from=access_region(machine,machine->rip,1,VM_EXECUTE,1);
    if(from==NULL)return 0;
    *out=*from;
    ++machine->rip;
    return 1;
}
static int get_code_dword(Machine *machine,uint32_t *out) {
    uint8_t b[4];
    unsigned int i;
    for(i=0;i<4;++i)
        if(!get_code_byte(machine,&b[i]))return 0;
    *out=(uint32_t)b[0]|(uint32_t)b[1]<<8|
         (uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
    return 1;
}
static int move_signed(uint64_t from,int64_t delta,uint64_t *target) {
    if(delta>=0) {
        if((uint64_t)delta>UINT64_MAX-from)return 0;
        *target=from+(uint64_t)delta;
    }else{
        uint64_t backwards=(uint64_t)(-delta);
        if(from<backwards)return 0;
        *target=from-backwards;
    }
    return 1;
}
static int read_dword(Machine *machine,uint64_t address,uint32_t *out) {
    const unsigned char *b=access_region(machine,address,4,VM_READ,0);
    if(b==NULL)return 0;
    *out=(uint32_t)b[0]|(uint32_t)b[1]<<8|
         (uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
    return 1;
}
static int write_dword(Machine *machine,uint64_t address,uint32_t value) {
    unsigned char *b=access_region(machine,address,4,VM_WRITE,0);
    if(b==NULL)return 0;
    b[0]=(unsigned char)value;
    b[1]=(unsigned char)(value>>8);
    b[2]=(unsigned char)(value>>16);
    b[3]=(unsigned char)(value>>24);
    return 1;
}
static int run_cpu(Machine *m,uint32_t step_limit,RyzMac1Result *out) {
    uint8_t op,extra;
    uint32_t imm;
    uint64_t target;
    int status=RYZ_MAC1_STEP_LIMIT;
    while(m->steps<step_limit) {
        m->last=m->rip;
        ++m->steps;
        if(!get_code_byte(m,&op)){status=RYZ_MAC1_EXEC_DENIED;break;}
        switch(op) {
        case 0x90: /* NOP */
            break;
        case 0xb8: /* MOV EAX,imm32: architectural zero-extension to RAX */
            if(!get_code_dword(m,&imm)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            m->eax=imm;
            break;
        case 0x05: /* ADD EAX,imm32, modulo 2^32 */
            if(!get_code_dword(m,&imm)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            m->eax+=imm;
            break;
        case 0x83: /* ADD EAX, sign-extended imm8, only ModRM C0 */
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(extra!=0xc0){status=RYZ_MAC1_OPCODE_DENIED;goto done;}
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            m->eax+=(uint32_t)(int32_t)(int8_t)extra;
            break;
        case 0x31: /* XOR EAX,EAX, only ModRM C0 */
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(extra!=0xc0){status=RYZ_MAC1_OPCODE_DENIED;goto done;}
            m->eax=0;
            break;
        case 0xff: /* INC EAX, only FF C0 */
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(extra!=0xc0){status=RYZ_MAC1_OPCODE_DENIED;goto done;}
            ++m->eax;
            break;
        case 0x8b: /* MOV EAX,[RIP+disp32], read permission required */
        case 0x89: /* MOV [RIP+disp32],EAX, write permission required */
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(extra!=0x05){status=RYZ_MAC1_OPCODE_DENIED;goto done;}
            if(!get_code_dword(m,&imm)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(!move_signed(m->rip,(int64_t)(int32_t)imm,&target)){
                status=op==0x8b?RYZ_MAC1_READ_DENIED:RYZ_MAC1_WRITE_DENIED;goto done;
            }
            if(op==0x8b) {
                if(!read_dword(m,target,&m->eax)){status=RYZ_MAC1_READ_DENIED;goto done;}
            }else if(!write_dword(m,target,m->eax)){
                status=RYZ_MAC1_WRITE_DENIED;goto done;
            }
            break;
        case 0xeb: /* JMP rel8, constrained by instruction budget and RX */
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(!move_signed(m->rip,(int64_t)(int8_t)extra,&target)){
                status=RYZ_MAC1_EXEC_DENIED;goto done;
            }
            m->rip=target;
            break;
        case 0xe9: /* JMP rel32 */
            if(!get_code_dword(m,&imm)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            if(!move_signed(m->rip,(int64_t)(int32_t)imm,&target)){
                status=RYZ_MAC1_EXEC_DENIED;goto done;
            }
            m->rip=target;
            break;
        case 0xc3: /* Synthetic test return sentinel; no Darwin stack exists. */
            out->returned_from_test_entry=1;
            status=RYZ_MAC1_OK;
            goto done;
        case 0x0f:
            if(!get_code_byte(m,&extra)){status=RYZ_MAC1_EXEC_DENIED;goto done;}
            status=extra==0x05?RYZ_MAC1_SYSCALL_DENIED:RYZ_MAC1_OPCODE_DENIED;
            goto done;
        default:
            status=RYZ_MAC1_OPCODE_DENIED;
            goto done;
        }
    }
done:
    out->eax=m->eax;
    out->last_rip=m->last;
    out->steps=m->steps;
    return status;
}

int ryz_mac1_run(const unsigned char *image,size_t size,
                 uint32_t step_limit,RyzMac1Result *out) {
    RyzMachoPlan plan;
    Machine *machine;
    uint64_t total=0;
    uint32_t i;
    int status=RYZ_MAC1_BAD_IMAGE;
    if(out!=NULL)memset(out,0,sizeof(*out));
    if(out==NULL || image==NULL || size<32 || size>RYZ_MAC1_INPUT_MAX)
        return RYZ_MAC1_BAD_IMAGE;
    if(step_limit==0 || step_limit>RYZ_MAC1_STEPS_MAX)
        return RYZ_MAC1_RESOURCE_DENIED;
    if(ryz_macho64_plan(image,size,&plan)!=0)
        return RYZ_MAC1_BAD_IMAGE;
    /* Heap-allocated VM keeps large memory separate from the host stack.
     * Every segment is copied; no guest-provided address is ever a host ptr. */
    machine=(Machine *)calloc(1,sizeof(*machine));
    if(machine==NULL)return RYZ_MAC1_RESOURCE_DENIED;
    machine->rip=plan.entry;
    for(i=0;i<plan.segment_count;++i) {
        const RyzMachoSegment *src=&plan.segments[i];
        Region *dst=&machine->segments[i];
        if(src->virtual_bytes>RYZ_MAC1_MAPPED_MAX-total ||
           src->file_bytes>src->virtual_bytes) {
            status=RYZ_MAC1_RESOURCE_DENIED;
            goto done;
        }
        total+=src->virtual_bytes;
        dst->base=src->virtual_address;
        dst->extent=src->virtual_bytes;
        dst->backed=src->file_bytes;
        dst->permissions=src->protection;
        if(src->virtual_bytes>SIZE_MAX){
            status=RYZ_MAC1_RESOURCE_DENIED;
            goto done;
        }
        dst->buffer=(unsigned char *)calloc((size_t)src->virtual_bytes,1);
        if(dst->buffer==NULL){
            status=RYZ_MAC1_RESOURCE_DENIED;
            goto done;
        }
        ++machine->count;
        if(src->file_bytes!=0)
            memcpy(dst->buffer,image+(size_t)src->file_offset,
                   (size_t)src->file_bytes);
    }
    status=run_cpu(machine,step_limit,out);
done:
    release_regions(machine);
    free(machine);
    return status;
}
