/* SPDX-License-Identifier: AGPL-3.0-only */
#include "process.h"
static uint64_t le(const unsigned char *p, unsigned int n)
{
    uint64_t v=0;
    unsigned int i;
    for(i=0;i<n;i++) v |= (uint64_t)p[i] << (i*8);
    return v;
}
static void put(RyzLinuxMemory *m, uint64_t at, uint64_t value)
{
    unsigned int i;
    for(i=0;i<8;i++) m->bytes[(size_t)(at-m->base)+i]=(unsigned char)(value>>(i*8));
}
static int string(RyzLinuxMemory *m, uint64_t *top, const char *s, uint64_t *address)
{
    size_t n;
    if(s==NULL) return 0;
    for(n=0;n<=256 && s[n]!=0;n++);
    if(n>256 || *top-m->stack<n+1) return 0;
    *top-=n+1;
    memcpy(m->bytes+(size_t)(*top-m->base),s,n+1);
    *address=*top;
    return 1;
}
int ryz_vm_run_process_elf(const unsigned char *image, size_t length,
    unsigned char *arena, size_t capacity, RyzLinuxFiles *files,
    const RyzProcessArgs *args, RyzLinuxWrite output, void *opaque, RyzVmResult *result)
{
    RyzElf64Plan plan;
    RyzLinuxMemory memory;
    RyzLinuxProcess process;
    uint64_t lowest=UINT64_MAX, highest=0, cap, top, stack, at, phdr=0, phoff;
    uint64_t av[RYZ_PROCESS_ARGS], ev[RYZ_PROCESS_ARGS];
    uint64_t aux[20], phnum;
    size_t i, j, words;
    if(result!=NULL) memset(result,0,sizeof(*result));
    if(files!=NULL) {
        if(files->input==NULL || files->output==NULL || files->input_size>RYZ_LINUX_FILE_MAX ||
           files->output_capacity==0 || files->output_capacity>RYZ_LINUX_FILE_MAX)
            return RYZ_VM_BAD_INPUT;
        files->output_size=0;
        memset(files->output,0,files->output_capacity);
    }
    if(image==NULL || arena==NULL || result==NULL || args==NULL ||
       args->argc==0 || args->argc>RYZ_PROCESS_ARGS || args->envc>RYZ_PROCESS_ARGS ||
       args->argv==NULL || (args->envc!=0 && args->envp==NULL) ||
       ryz_elf64_plan(image,length,&plan)!=RYZ_ELF_OK)
        return RYZ_VM_BAD_INPUT;
    cap=capacity<RYZ_VM_MAX_SPAN?capacity:RYZ_VM_MAX_SPAN;
    cap &= ~(uint64_t)(RYZ_PAGE-1);
    for(i=0;i<plan.load_count;i++) {
        if(plan.loads[i].map_start<lowest) lowest=plan.loads[i].map_start;
        if(plan.loads[i].map_end>highest) highest=plan.loads[i].map_end;
    }
    if(cap<RYZ_PROCESS_STACK+2*RYZ_PAGE || highest-lowest>cap-RYZ_PROCESS_STACK-RYZ_PAGE || lowest>UINT64_MAX-cap)
        return RYZ_VM_MAP_ERROR;
    memset(&memory,0,sizeof(memory));
    memory.bytes=arena; memory.base=lowest; memory.size=cap;
    memory.heap=memory.brk=highest; memory.stack=lowest+cap-RYZ_PROCESS_STACK;
    memset(arena,0,(size_t)cap);
    phoff=le(image+32,8); phnum=le(image+56,2);
    for(i=0;i<plan.load_count;i++) {
        RyzElf64Segment *s=&plan.loads[i];
        if(ryz_elf64_materialize(image,length,s,arena+(size_t)(s->address-lowest),
                                (size_t)(cap-(s->address-lowest)))!=RYZ_ELF_OK)
            return RYZ_VM_MAP_ERROR;
        for(j=(size_t)((s->map_start-lowest)/RYZ_PAGE);j<(s->map_end-lowest)/RYZ_PAGE;j++)
            memory.pages[j]=(unsigned char)(RYZ_MAP|s->flags);
        if(phoff>=s->file_offset && phoff-s->file_offset<=s->file_bytes &&
           phnum*56<=s->file_bytes-(phoff-s->file_offset))
            phdr=s->address+phoff-s->file_offset;
    }
    if(phdr==0 || !ryz_memory_access(&memory,phdr,phnum*56,RYZ_READ))return RYZ_VM_BAD_INPUT;
    for(i=(size_t)((memory.stack-lowest)/RYZ_PAGE);i<cap/RYZ_PAGE;i++)
        memory.pages[i]=RYZ_MAP|RYZ_READ|RYZ_WRITE;
    top=lowest+cap;
    for(i=0;i<args->argc;i++) if(!string(&memory,&top,args->argv[i],&av[i])) return RYZ_VM_BAD_INPUT;
    for(i=0;i<args->envc;i++) if(!string(&memory,&top,args->envp[i],&ev[i])) return RYZ_VM_BAD_INPUT;
    aux[0]=3; aux[1]=phdr; aux[2]=4; aux[3]=56; aux[4]=5; aux[5]=phnum;
    aux[6]=6; aux[7]=RYZ_PAGE; aux[8]=9; aux[9]=plan.entry;
    aux[10]=11; aux[11]=1000; aux[12]=12; aux[13]=1000;
    aux[14]=13; aux[15]=1000; aux[16]=14; aux[17]=1000;
    aux[18]=0; aux[19]=0;
    words=1+args->argc+1+args->envc+1+20;
    stack=(top-words*8)&~UINT64_C(15);
    if(stack<memory.stack) return RYZ_VM_MAP_ERROR;
    at=stack; put(&memory,at,args->argc); at+=8;
    for(i=0;i<args->argc;i++,at+=8) put(&memory,at,av[i]);
    put(&memory,at,0); at+=8;
    for(i=0;i<args->envc;i++,at+=8) put(&memory,at,ev[i]);
    put(&memory,at,0); at+=8;
    for(i=0;i<20;i++,at+=8) put(&memory,at,aux[i]);
    if(ryz_linux_process_init(&process,1,1000,1000,1000,lowest,arena,(size_t)cap,output,opaque)!=0)
        return RYZ_VM_MAP_ERROR;
    process.files=files;
    process.memory_context=&memory;
    process.memory_read=ryz_memory_read; process.memory_write=ryz_memory_write;
    process.memory_call=ryz_memory_call;
    return ryz_cpu_run(&process,&memory,plan.entry,stack,result);
}
