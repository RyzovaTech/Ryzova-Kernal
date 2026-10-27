/* SPDX-License-Identifier: AGPL-3.0-only */
/* Cooperative bounded guest processes. No native fork, exec or pipe forwarding. */
#include "jobs.h"
#ifndef RYZ_PLAN9
#include <stdlib.h>
#endif
#define FREE 0
#define RUN 1
#define VFORK_WAIT 2
#define ZOMBIE 3
typedef struct Task {
    RyzCpu cpu;
    RyzLinuxMemory memory;
    RyzLinuxProcess process;
    int state,owned,vfork_parent;
} Task;
typedef struct Jobs {
    RyzLinuxWorld world;
    Task tasks[RYZ_JOB_TASKS];
    size_t capacity;
    uint32_t next_pid;
    unsigned int forks;
} Jobs;
typedef struct ExecArgs {
    char av[RYZ_PROCESS_ARGS][257],ev[RYZ_PROCESS_ARGS][257];
    const char *argv[RYZ_PROCESS_ARGS],*envp[RYZ_PROCESS_ARGS];
    RyzProcessArgs args;
} ExecArgs;
static uint64_t little(const unsigned char *b,unsigned int n)
{
    uint64_t v=0;unsigned int i;for(i=0;i<n;i++)v|=(uint64_t)b[i]<<(8*i);return v;
}
static void encode(unsigned char *b,uint64_t value,unsigned int n)
{
    unsigned int i;for(i=0;i<n;i++)b[i]=(unsigned char)(value>>(8*i));
}
static int guest_string(RyzCpu *c,uint64_t at,char *out,size_t maximum)
{
    size_t i;
    for(i=0;i<maximum;i++){
        if(at>UINT64_MAX-i || !ryz_memory_access(c->m,at+i,1,RYZ_READ))return -14;
        out[i]=(char)c->m->bytes[(size_t)(at+i-c->m->base)];
        if(out[i]==0)return 0;
    }
    return -7;
}
static int vector(RyzCpu *c,uint64_t at,char strings[RYZ_PROCESS_ARGS][257],const char **pointers,size_t *count)
{
    uint64_t pointer;size_t i;int result;
    if(at==0)return -14;
    for(i=0;i<=RYZ_PROCESS_ARGS;i++){
        if(at>UINT64_MAX-i*8 || !ryz_memory_access(c->m,at+i*8,8,RYZ_READ))return -14;
        pointer=little(c->m->bytes+(size_t)(at+i*8-c->m->base),8);
        if(pointer==0){*count=i;return 0;}
        if(i==RYZ_PROCESS_ARGS)return -7;
        result=guest_string(c,pointer,strings[i],257);if(result)return result;
        pointers[i]=strings[i];
    }
    return -7;
}
static void release_vfork(Jobs *jobs,Task *task)
{
    if(task->vfork_parent>=0){jobs->tasks[task->vfork_parent].state=RUN;task->vfork_parent=-1;}
}
static void exited(Jobs *jobs,Task *task)
{
    unsigned int i;
    if(task->cpu.tid_address && ryz_memory_access(task->cpu.m,task->cpu.tid_address,4,RYZ_WRITE))
        memset(task->cpu.m->bytes+(size_t)(task->cpu.tid_address-task->cpu.m->base),0,4);
    ryz_world_close(&task->process,0);task->state=ZOMBIE;release_vfork(jobs,task);
    for(i=1;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE &&
        jobs->tasks[i].process.parent_pid==task->process.ns.pid)
        jobs->tasks[i].process.parent_pid=jobs->tasks[0].process.ns.pid;
}
static int64_t fork_task(Jobs *jobs,Task *parent,int vfork)
{
    Task *child;unsigned int i;unsigned char *bytes=NULL;
    if(jobs->forks>=RYZ_JOB_FORKS || parent->vfork_parent>=0)return -11;
    for(i=1;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state==FREE)break;
    if(i==RYZ_JOB_TASKS)return -11;
    if(!vfork){bytes=malloc((size_t)parent->cpu.m->size);if(!bytes)return -12;memcpy(bytes,parent->cpu.m->bytes,(size_t)parent->cpu.m->size);}
    child=&jobs->tasks[i];memset(child,0,sizeof(*child));child->vfork_parent=-1;
    child->process=parent->process;ryz_world_fork(&parent->process,&child->process);
    child->process.ns.pid=jobs->next_pid++;child->process.parent_pid=parent->process.ns.pid;
    child->cpu=parent->cpu;child->cpu.p=&child->process;child->cpu.r[0]=0;
    child->cpu.ip=parent->cpu.cur;child->cpu.r[1]=parent->cpu.cur;child->cpu.r[11]=parent->cpu.flags;child->cpu.tid_address=0;
    if(vfork){child->vfork_parent=(int)(parent-jobs->tasks);parent->state=VFORK_WAIT;}
    else{
        child->memory=*parent->cpu.m;child->memory.bytes=bytes;child->owned=1;
        child->cpu.m=&child->memory;child->process.guest_bytes=bytes;child->process.memory_context=&child->memory;
    }
    child->state=RUN;jobs->forks++;parent->cpu.result->forks++;
    {unsigned int live=0;for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE)live++;
     if(live>parent->cpu.result->peak_tasks)parent->cpu.result->peak_tasks=live;}
    return (int64_t)child->process.ns.pid;
}
static int64_t wait_task(Jobs *jobs,Task *parent,const RyzLinuxRegs *r)
{
    unsigned int i;Task *child=NULL;int found=0;int64_t wanted=(int64_t)(int32_t)r->rdi;
    if(r->rdx & ~UINT64_C(11))return -22;
    if(r->rsi && !ryz_memory_access(parent->cpu.m,r->rsi,4,RYZ_WRITE))return -14;
    if(r->r10 && !ryz_memory_access(parent->cpu.m,r->r10,144,RYZ_WRITE))return -14;
    for(i=1;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE &&
        jobs->tasks[i].process.parent_pid==parent->process.ns.pid){
        Task *candidate=&jobs->tasks[i];
        if(wanted>0 && (uint64_t)wanted!=candidate->process.ns.pid)continue;
        if(wanted==0 && candidate->process.group_pid!=parent->process.group_pid)continue;
        if(wanted < -1 && (-(uint64_t)wanted)!=candidate->process.group_pid)continue;
        found=1;if(candidate->state==ZOMBIE){child=candidate;break;}
    }
    if(!found)return -10;
    if(!child)return r->rdx&1?0:RYZ_LINUX_BLOCKED;
    wanted=child->process.ns.pid;
    if(r->rsi)encode(parent->cpu.m->bytes+(size_t)(r->rsi-parent->cpu.m->base),(uint64_t)child->process.exit_status<<8,4);
    if(r->r10)memset(parent->cpu.m->bytes+(size_t)(r->r10-parent->cpu.m->base),0,144);
    if(child->owned)free(child->memory.bytes);
    memset(child,0,sizeof(*child));child->vfork_parent=-1;return wanted;
}
static int exec_task(Jobs *jobs,Task *task,const RyzLinuxRegs *r,int64_t *answer)
{
    ExecArgs *snapshot;RyzLinuxMemory *next;RyzVmResult *result=task->cpu.result;
    unsigned char *bytes;char path[257];size_t i;uint64_t entry,stack;int status;const RyzLinuxExec *grant=NULL;
    if(result->execs>=RYZ_JOB_EXECS){*answer=-11;return RYZ_VM_OK;}
    status=guest_string(&task->cpu,r->rdi,path,sizeof(path));
    if(status){*answer=status;return RYZ_VM_OK;}
    for(i=0;i<jobs->world.exec_count;i++)if(strcmp(path,jobs->world.execs[i].path)==0)grant=&jobs->world.execs[i];
    if(!grant){*answer=-2;return RYZ_VM_OK;}
    snapshot=malloc(sizeof(*snapshot));next=malloc(sizeof(*next));
    if(!snapshot || !next){free(snapshot);free(next);*answer=-12;return RYZ_VM_OK;}
    memset(snapshot,0,sizeof(*snapshot));
    status=vector(&task->cpu,r->rsi,snapshot->av,snapshot->argv,&snapshot->args.argc);
    if(!status && r->rdx)status=vector(&task->cpu,r->rdx,snapshot->ev,snapshot->envp,&snapshot->args.envc);
    if(!status && snapshot->args.argc==0)status=-22;
    if(status){free(snapshot);free(next);*answer=status;return RYZ_VM_OK;}
    snapshot->args.argv=snapshot->argv;snapshot->args.envp=snapshot->envp;
    bytes=malloc(jobs->capacity);
    if(!bytes){free(snapshot);free(next);*answer=-12;return RYZ_VM_OK;}
    status=ryz_prepare_process(grant->image,grant->size,bytes,jobs->capacity,&snapshot->args,next,&entry,&stack);
    free(snapshot);
    if(status!=RYZ_VM_OK){free(bytes);free(next);*answer=-8;return RYZ_VM_OK;}
    ryz_world_close(&task->process,1);
    if(task->owned)free(task->memory.bytes);
    task->memory=*next;free(next);task->owned=1;
    task->process.guest_base=task->memory.base;task->process.guest_bytes=bytes;task->process.guest_size=(size_t)task->memory.size;
    task->process.memory_context=&task->memory;
    for(i=0;i<64;i++)if(little(task->process.signal_actions[i],8)!=1)memset(task->process.signal_actions[i],0,32);
    ryz_cpu_init(&task->cpu,&task->process,&task->memory,entry,stack,result);task->cpu.cur=entry;
    release_vfork(jobs,task);result->execs++;return RYZ_CPU_EXECUTED;
}
static int job_call(void *context,void *cpu,const RyzLinuxRegs *r,int64_t *answer)
{
    Jobs *jobs=context;Task *task=NULL;unsigned int i;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(&jobs->tasks[i].cpu==cpu){task=&jobs->tasks[i];break;}
    if(!task)return RYZ_VM_BAD_INPUT;
    if(r->rax==57 || r->rax==58)*answer=fork_task(jobs,task,r->rax==58);
    else if(r->rax==61)*answer=wait_task(jobs,task,r);
    else if(r->rax==59)return exec_task(jobs,task,r,answer);
    else *answer=-38;
    return *answer==RYZ_LINUX_BLOCKED?RYZ_CPU_BLOCKED:RYZ_VM_OK;
}
static int valid_path(const char *path,size_t length)
{
    size_t i,start=1,n;
    if(length<2 || length>=RYZ_NS_PATH_MAX || path[0]!='/')return 0;
    if(strcmp(path,"/input")==0 || strcmp(path,"/output")==0 || strcmp(path,"/dev/null")==0 ||
       strcmp(path,"/dev/zero")==0 || strcmp(path,"/tmp")==0 || strcmp(path,"/proc/self")==0 ||
       strncmp(path,"/compat/linux",13)==0)return 0;
    for(i=1;i<=length;i++)if(i==length || path[i]=='/'){
        n=i-start;if(n==0 || (n==1 && path[start]=='.') || (n==2 && path[start]=='.' && path[start+1]=='.'))return 0;
        start=i+1;
    }
    return 1;
}
int ryz_vm_run_jobs_elf(const unsigned char *image,size_t length,unsigned char *arena,size_t capacity,
    RyzLinuxFiles *files,const RyzProcessArgs *args,const RyzJobConfig *config,RyzLinuxWrite output,void *opaque,RyzVmResult *result)
{
    Jobs *jobs;Task *root;uint64_t entry,stack;unsigned int i,j,q;size_t n;int status,progress;
    if(result)memset(result,0,sizeof(*result));
    if(files){
        if(!files->input || !files->output || files->input_size>RYZ_LINUX_FILE_MAX ||
           files->output_capacity==0 || files->output_capacity>RYZ_LINUX_FILE_MAX)return RYZ_VM_BAD_INPUT;
        files->output_size=0;memset(files->output,0,files->output_capacity);
    }
    if(!result || !config || config->exec_count>RYZ_PROCESS_ARGS || (config->exec_count && !config->execs))return RYZ_VM_BAD_INPUT;
    for(i=0;i<config->exec_count;i++){
        if(!config->execs[i].path || config->execs[i].path[0]!='/')return RYZ_VM_BAD_INPUT;
        for(n=0;n<=256 && config->execs[i].path[n];n++);
        if(!valid_path(config->execs[i].path,n) || !config->execs[i].image || config->execs[i].size==0 || config->execs[i].size>RYZ_PROCESS_IMAGE_MAX)return RYZ_VM_BAD_INPUT;
        for(j=0;j<i;j++)if(strcmp(config->execs[j].path,config->execs[i].path)==0)return RYZ_VM_BAD_INPUT;
    }
    jobs=malloc(sizeof(*jobs));if(!jobs)return RYZ_VM_BAD_INPUT;memset(jobs,0,sizeof(*jobs));
    for(i=0;i<RYZ_JOB_TASKS;i++)jobs->tasks[i].vfork_parent=-1;
    jobs->capacity=capacity<RYZ_PROCESS_MAX_SPAN?capacity:RYZ_PROCESS_MAX_SPAN;
    jobs->next_pid=1001;jobs->world.execs=config->execs;jobs->world.exec_count=config->exec_count;
    root=&jobs->tasks[0];status=ryz_prepare_process(image,length,arena,capacity,args,&root->memory,&entry,&stack);
    if(status!=RYZ_VM_OK){free(jobs);return status;}
    if(ryz_linux_process_init(&root->process,1,1000,1000,1000,root->memory.base,arena,(size_t)root->memory.size,output,opaque)!=0){free(jobs);return RYZ_VM_BAD_INPUT;}
    root->process.parent_pid=1;root->process.files=files;
    root->process.memory_context=&root->memory;root->process.memory_read=ryz_memory_read;root->process.memory_write=ryz_memory_write;root->process.memory_call=ryz_memory_call;
    root->process.job_call=job_call;root->process.job_context=jobs;
    ryz_world_attach(&root->process,&jobs->world);root->state=RUN;result->peak_tasks=1;
    ryz_cpu_init(&root->cpu,&root->process,&root->memory,entry,stack,result);
    status=RYZ_VM_OK;
    while(root->state!=ZOMBIE){
        progress=0;
        for(i=0;i<RYZ_JOB_TASKS && root->state!=ZOMBIE;i++){
            Task *task=&jobs->tasks[i];if(task->state!=RUN)continue;
            for(q=0;q<RYZ_JOB_QUANTUM && task->state==RUN;q++){
                status=ryz_cpu_tick(&task->cpu);
                if(status==RYZ_CPU_BLOCKED){result->blocked_syscalls++;status=RYZ_VM_OK;break;}
                if(status!=RYZ_VM_OK)goto done;
                progress=1;
                if(task->process.exited){exited(jobs,task);break;}
            }
        }
        if(!progress){status=RYZ_JOB_DEADLOCK;break;}
    }
    if(root->state==ZOMBIE){result->exited=1;result->exit_status=root->process.exit_status;}
 done:
    result->pipe_bytes=jobs->world.pipe_bytes;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE)ryz_world_close(&jobs->tasks[i].process,0);
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].owned)free(jobs->tasks[i].memory.bytes);
    free(jobs);return status;
}
