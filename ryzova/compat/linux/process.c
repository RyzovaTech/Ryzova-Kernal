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
int ryz_prepare_process(const unsigned char *image,size_t length,
    unsigned char *arena,size_t capacity,const RyzProcessArgs *args,
    RyzLinuxMemory *memory,uint64_t *entry,uint64_t *initial_stack)
{
    RyzElf64Plan plan;
    uint64_t lowest=UINT64_MAX,highest=0,cap,top,stack,at,phdr=0,phoff;
    uint64_t av[RYZ_PROCESS_ARGS],ev[RYZ_PROCESS_ARGS],aux[20],phnum;
    size_t i,j,words;
    if(image==NULL || length>RYZ_PROCESS_IMAGE_MAX || arena==NULL || memory==NULL || args==NULL ||
       args->argc==0 || args->argc>RYZ_PROCESS_ARGS || args->envc>RYZ_PROCESS_ARGS ||
       args->argv==NULL || (args->envc!=0 && args->envp==NULL) ||
       ryz_elf64_plan(image,length,&plan)!=RYZ_ELF_OK)return RYZ_VM_BAD_INPUT;
    cap=capacity<RYZ_PROCESS_MAX_SPAN?capacity:RYZ_PROCESS_MAX_SPAN;
    cap &= ~(uint64_t)(RYZ_PAGE-1);
    for(i=0;i<plan.load_count;i++) {
        if(plan.loads[i].map_start<lowest) lowest=plan.loads[i].map_start;
        if(plan.loads[i].map_end>highest) highest=plan.loads[i].map_end;
    }
    if(cap<RYZ_PROCESS_STACK+2*RYZ_PAGE || highest-lowest>cap-RYZ_PROCESS_STACK-RYZ_PAGE || lowest>UINT64_MAX-cap || lowest>UINT64_C(0x0000800000000000)-cap)
        return RYZ_VM_MAP_ERROR;
    memset(memory,0,sizeof(*memory));
    memory->bytes=arena; memory->base=lowest; memory->size=cap;
    memory->heap=memory->brk=highest; memory->stack=lowest+cap-RYZ_PROCESS_STACK;
    memset(arena,0,(size_t)cap);
    phoff=le(image+32,8); phnum=le(image+56,2);
    for(i=0;i<plan.load_count;i++) {
        RyzElf64Segment *s=&plan.loads[i];
        if(ryz_elf64_materialize(image,length,s,arena+(size_t)(s->address-lowest),
                                (size_t)(cap-(s->address-lowest)))!=RYZ_ELF_OK)
            return RYZ_VM_MAP_ERROR;
        for(j=(size_t)((s->map_start-lowest)/RYZ_PAGE);j<(s->map_end-lowest)/RYZ_PAGE;j++)
            memory->pages[j]=(unsigned char)(RYZ_MAP|s->flags);
        if(phoff>=s->file_offset && phoff-s->file_offset<=s->file_bytes &&
           phnum*56<=s->file_bytes-(phoff-s->file_offset))
            phdr=s->address+phoff-s->file_offset;
    }
    if(phdr==0 || !ryz_memory_access(memory,phdr,phnum*56,RYZ_READ))return RYZ_VM_BAD_INPUT;
    for(i=(size_t)((memory->stack-lowest)/RYZ_PAGE);i<cap/RYZ_PAGE;i++)
        memory->pages[i]=RYZ_MAP|RYZ_READ|RYZ_WRITE;
    top=lowest+cap;
    for(i=0;i<args->argc;i++) if(!string(memory,&top,args->argv[i],&av[i])) return RYZ_VM_BAD_INPUT;
    for(i=0;i<args->envc;i++) if(!string(memory,&top,args->envp[i],&ev[i])) return RYZ_VM_BAD_INPUT;
    aux[0]=3; aux[1]=phdr; aux[2]=4; aux[3]=56; aux[4]=5; aux[5]=phnum;
    aux[6]=6; aux[7]=RYZ_PAGE; aux[8]=9; aux[9]=plan.entry;
    aux[10]=11; aux[11]=1000; aux[12]=12; aux[13]=1000;
    aux[14]=13; aux[15]=1000; aux[16]=14; aux[17]=1000;
    aux[18]=0; aux[19]=0;
    words=1+args->argc+1+args->envc+1+20;
    stack=(top-words*8)&~UINT64_C(15);
    if(stack<memory->stack) return RYZ_VM_MAP_ERROR;
    at=stack; put(memory,at,args->argc); at+=8;
    for(i=0;i<args->argc;i++,at+=8) put(memory,at,av[i]);
    put(memory,at,0); at+=8;
    for(i=0;i<args->envc;i++,at+=8) put(memory,at,ev[i]);
    put(memory,at,0); at+=8;
    for(i=0;i<20;i++,at+=8) put(memory,at,aux[i]);
    *entry=plan.entry;*initial_stack=stack;return RYZ_VM_OK;
}
int ryz_vm_run_process_elf(const unsigned char *image,size_t length,
    unsigned char *arena,size_t capacity,RyzLinuxFiles *files,
    const RyzProcessArgs *args,RyzLinuxWrite output,void *opaque,RyzVmResult *result)
{
    RyzLinuxMemory memory;
    RyzLinuxProcess process;
    uint64_t entry,stack;
    int status;
    if(result!=NULL)memset(result,0,sizeof(*result));
    if(files!=NULL){
        if(files->input==NULL || files->output==NULL || files->input_size>RYZ_LINUX_FILE_MAX ||
           files->output_capacity==0 || files->output_capacity>RYZ_LINUX_FILE_MAX)return RYZ_VM_BAD_INPUT;
        files->output_size=0;memset(files->output,0,files->output_capacity);
    }
    if(result==NULL)return RYZ_VM_BAD_INPUT;
    status=ryz_prepare_process(image,length,arena,capacity,args,&memory,&entry,&stack);
    if(status!=RYZ_VM_OK)return status;
    if(ryz_linux_process_init(&process,1,1000,1000,1000,memory.base,arena,(size_t)memory.size,output,opaque)!=0)return RYZ_VM_MAP_ERROR;
    process.files=files;process.memory_context=&memory;
    process.memory_read=ryz_memory_read;process.memory_write=ryz_memory_write;process.memory_call=ryz_memory_call;
    return ryz_cpu_run(&process,&memory,entry,stack,result);
}

/* Opt-in job loader: kernel loads the main ELF and its explicitly granted
 * interpreter; the unmodified guest linker performs relocations and TLS. */
int ryz_prepare_job(const unsigned char *image,size_t length,unsigned char *arena,size_t capacity,
    const RyzProcessArgs *args,RyzLinuxWorld *world,RyzLinuxMemory *m,uint64_t *entry,uint64_t *initial_stack)
{
    RyzElf64Plan plans[2],strict;const unsigned char *images[2];size_t sizes[2],count=1,i,j,k,words;
    uint64_t bias,low=UINT64_MAX,high=0,main_high=0,phoff,phnum,phdr=0,interp_base=0,cap,top,stack,at;
    uint64_t av[RYZ_PROCESS_ARGS],ev[RYZ_PROCESS_ARGS],aux[28],random;
    const RyzLinuxExec *interpreter=NULL;const char *path=NULL;unsigned int found=0;
    if(ryz_elf64_plan(image,length,&strict)==RYZ_ELF_OK)return ryz_prepare_process(image,length,arena,capacity,args,m,entry,initial_stack);
    if(!image || length<64 || length>RYZ_PROCESS_IMAGE_MAX || !arena || !args || !m || !world || !world->random ||
       !args->argc || args->argc>RYZ_PROCESS_ARGS || args->envc>RYZ_PROCESS_ARGS || !args->argv || (args->envc && !args->envp))return RYZ_VM_BAD_INPUT;
    bias=le(image+16,2)==3?UINT64_C(0x400000):0;
    if(ryz_elf64_plan_relocated(image,length,bias,1,&plans[0])!=RYZ_ELF_OK)return RYZ_VM_BAD_INPUT;
    phoff=le(image+32,8);phnum=le(image+56,2);
    for(i=0;i<phnum;i++)if(le(image+(size_t)phoff+i*56,4)==3){
        if(found++)return RYZ_VM_BAD_INPUT;
        path=(const char *)(image+(size_t)le(image+(size_t)phoff+i*56+8,8));
    }
    images[0]=image;sizes[0]=length;
    if(path){
        for(i=0;i<world->exec_count;i++)if(strcmp(path,world->execs[i].path)==0)interpreter=&world->execs[i];
        if(!interpreter)return RYZ_VM_BAD_INPUT;
        interp_base=UINT64_C(0x800000);
        if(interpreter->size<64 || le(interpreter->image+16,2)!=3 ||
            ryz_elf64_plan_relocated(interpreter->image,interpreter->size,interp_base,1,&plans[1])!=RYZ_ELF_OK)return RYZ_VM_BAD_INPUT;
        for(i=0;i<le(interpreter->image+56,2);i++)if(le(interpreter->image+(size_t)le(interpreter->image+32,8)+i*56,4)==3)return RYZ_VM_BAD_INPUT;
        images[1]=interpreter->image;sizes[1]=interpreter->size;count=2;
    }
    for(k=0;k<count;k++)for(i=0;i<plans[k].load_count;i++){
        RyzElf64Segment *s=&plans[k].loads[i];
        if(s->map_start<low)low=s->map_start;
        if(s->map_end>high)high=s->map_end;
        if(k==0 && s->map_end>main_high)main_high=s->map_end;
        if(k)for(j=0;j<plans[0].load_count;j++)if(s->map_start<plans[0].loads[j].map_end && plans[0].loads[j].map_start<s->map_end)return RYZ_VM_MAP_ERROR;
    }
    cap=(capacity<RYZ_PROCESS_MAX_SPAN?capacity:RYZ_PROCESS_MAX_SPAN)&~UINT64_C(4095);
    if(cap<RYZ_PROCESS_STACK+2*RYZ_PAGE || high-low>cap-RYZ_PROCESS_STACK-RYZ_PAGE || low>UINT64_C(0x0000800000000000)-cap)return RYZ_VM_MAP_ERROR;
    memset(m,0,sizeof(*m));memset(arena,0,(size_t)cap);m->bytes=arena;m->base=low;m->size=cap;m->dynamic=1;
    m->heap=m->brk=main_high;m->stack=low+cap-RYZ_PROCESS_STACK;
    for(k=0;k<count;k++)for(i=0;i<plans[k].load_count;i++){
        RyzElf64Segment *s=&plans[k].loads[i];
        if(ryz_elf64_materialize(images[k],sizes[k],s,arena+(size_t)(s->address-low),(size_t)(cap-(s->address-low)))!=RYZ_ELF_OK)return RYZ_VM_MAP_ERROR;
        for(j=(size_t)((s->map_start-low)/RYZ_PAGE);j<(s->map_end-low)/RYZ_PAGE;j++)m->pages[j]=(unsigned char)(RYZ_MAP|s->flags|((s->flags&RYZ_EXEC)?64:0));
        if(k==0 && phoff>=s->file_offset && phoff-s->file_offset<=s->file_bytes && phnum*56<=s->file_bytes-(phoff-s->file_offset))phdr=s->address+phoff-s->file_offset;
    }
    if(!phdr || !ryz_memory_access(m,phdr,phnum*56,RYZ_READ))return RYZ_VM_BAD_INPUT;
    for(i=(size_t)((m->stack-low)/RYZ_PAGE);i<cap/RYZ_PAGE;i++)m->pages[i]=RYZ_MAP|RYZ_READ|RYZ_WRITE;
    top=low+cap;
    for(i=0;i<args->argc;i++)if(!string(m,&top,args->argv[i],&av[i]))return RYZ_VM_BAD_INPUT;
    for(i=0;i<args->envc;i++)if(!string(m,&top,args->envp[i],&ev[i]))return RYZ_VM_BAD_INPUT;
    top-=16;random=top;
    if(ryz_world_random(world,arena+(size_t)(top-low),16)!=16)return RYZ_VM_BAD_INPUT;
    aux[0]=3;aux[1]=phdr;aux[2]=4;aux[3]=56;aux[4]=5;aux[5]=phnum;
    aux[6]=6;aux[7]=RYZ_PAGE;aux[8]=7;aux[9]=interp_base;aux[10]=9;aux[11]=plans[0].entry;
    aux[12]=11;aux[13]=1000;aux[14]=12;aux[15]=1000;aux[16]=13;aux[17]=1000;aux[18]=14;aux[19]=1000;
    aux[20]=23;aux[21]=0;aux[22]=25;aux[23]=random;aux[24]=31;aux[25]=av[0];aux[26]=0;aux[27]=0;
    words=1+args->argc+1+args->envc+1+28;stack=(top-words*8)&~UINT64_C(15);
    if(stack<m->stack)return RYZ_VM_MAP_ERROR;
    at=stack;put(m,at,args->argc);at+=8;
    for(i=0;i<args->argc;i++,at+=8)put(m,at,av[i]);
    put(m,at,0);at+=8;
    for(i=0;i<args->envc;i++,at+=8)put(m,at,ev[i]);
    put(m,at,0);at+=8;
    for(i=0;i<28;i++,at+=8)put(m,at,aux[i]);
    *entry=plans[count-1].entry;*initial_stack=stack;return RYZ_VM_OK;
}
