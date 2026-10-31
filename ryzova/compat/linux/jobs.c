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
#define STOPPED 4
typedef struct SignalEvent {
    unsigned int sig,pid,uid;
    int code,status;
    uint64_t sequence,address;
} SignalEvent;
typedef struct FutexRestart {uint64_t frame,ip,address,deadline;int active;} FutexRestart;
typedef struct Task {
    RyzCpu cpu;
    RyzLinuxProcess process;
    int state,vfork_parent,mm_held;
    unsigned int mm;
    uint32_t vfork_parent_pid,vfork_wait_token,vfork_token;
    int blocked,suspended,term_signal,stop_event,continue_event;
    int executed,thread,notified,futex_waiting,futex_woken,yielded;
    struct Task *leader;
    uint64_t futex_address,futex_deadline,robust_head,poll_deadline;
    int poll_active;
    uint32_t futex_mask;
    RyzFutexKey futex_key;
    FutexRestart futex_frames[8],futex_restart;
    uint64_t suspend_mask,alt_sp,alt_size,signal_sequence;
    unsigned int signal_depth;
    int sleep_kind;
    uint64_t sleep_deadline,sleep_remaining,alarm_deadline,alarm_interval;
    SignalEvent signals[64],process_signals[64];
} Task;
typedef struct MemorySlot {RyzLinuxMemory memory;unsigned int refs;int used,owned;} MemorySlot;
typedef struct Jobs {
    MemorySlot memories[RYZ_JOB_TASKS];
    RyzLinuxWorld world;
    Task tasks[RYZ_JOB_TASKS];
    size_t capacity;
    uint64_t arena_bytes,arena_peak,arena_limit;
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
#include "filesystem_state.h"
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
static unsigned char *arena_alloc(Jobs *jobs,size_t size)
{
    unsigned char *p;if(size>jobs->arena_limit-jobs->arena_bytes)return NULL;
    p=malloc(size);if(p){jobs->arena_bytes+=size;if(jobs->arena_bytes>jobs->arena_peak)jobs->arena_peak=jobs->arena_bytes;}return p;
}
static void arena_free(Jobs *jobs,unsigned char *bytes,size_t size)
{if(bytes){free(bytes);jobs->arena_bytes-=size;}}
static void mm_release(Jobs *jobs,Task *task)
{
    MemorySlot *slot;
    if(!task->mm_held)return;
    slot=&jobs->memories[task->mm];task->mm_held=0;
    ryz_memory_commit(&slot->memory,1);
    if(--slot->refs==0){ryz_memory_drop(&slot->memory);jobs->world.memory_barriers[task->mm]=0;if(slot->owned)arena_free(jobs,slot->memory.bytes,(size_t)slot->memory.size);else jobs->arena_bytes-=jobs->capacity;memset(slot,0,sizeof(*slot));}
}
static int mm_free(Jobs *jobs)
{
    unsigned int i;for(i=0;i<RYZ_JOB_TASKS;i++)if(!jobs->memories[i].used)return (int)i;
    return -1;
}
static Task *group_leader(Jobs *jobs,Task *task)
{
    unsigned int i;for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.ns.pid==task->process.tgid)return &jobs->tasks[i];
    return task;
}
static int group_live(Jobs *jobs,uint32_t tgid)
{
    unsigned int i;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].state!=ZOMBIE && jobs->tasks[i].process.tgid==tgid)return 1;
    return 0;
}
static void group_exit(Jobs *jobs,Task *task,unsigned int signal,unsigned int code)
{
    unsigned int i;Task *leader=group_leader(jobs,task);
    leader->term_signal=(int)signal;leader->process.exit_status=(uint8_t)code;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.tgid==task->process.tgid){
        jobs->tasks[i].process.exited=1;jobs->tasks[i].process.exit_status=(uint8_t)code;jobs->tasks[i].term_signal=(int)signal;
        if(jobs->tasks[i].state==STOPPED)jobs->tasks[i].state=RUN;
    }
}
static int futex_wake(Jobs *,Task *,uint64_t,uint32_t,uint32_t);
static void robust_exit(Jobs *,Task *);
static void exited(Jobs *,Task *);
static int timer_interrupt(Task *);
#include "jobs_futex.h"
#include "jobs_signals.h"
#include "jobs_timers.h"

static void release_vfork(Jobs *jobs,Task *task)
{
    if(task->vfork_parent>=0){Task *parent=&jobs->tasks[task->vfork_parent];if(parent->state==VFORK_WAIT && parent->process.ns.pid==task->vfork_parent_pid && parent->vfork_wait_token==task->vfork_token)parent->state=RUN;task->vfork_parent=-1;}
}
static void finish_group(Jobs *jobs,Task *leader,Task *last)
{
    unsigned int i;Task *parent;
    if(group_live(jobs,leader->process.tgid) || leader->notified)return;
    leader->notified=1;leader->term_signal=last->term_signal;leader->process.exit_status=last->process.exit_status;
    child_notification(jobs,leader,leader->term_signal?2:1,leader->term_signal?leader->term_signal:leader->process.exit_status);
    for(i=1;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.parent_pid==leader->process.tgid)
        jobs->tasks[i].process.parent_pid=jobs->tasks[0].process.tgid;
    parent=task_parent(jobs,leader);
    if(leader!=&jobs->tasks[0] && parent && (little(RYZ_ACTION(&parent->process,16),8)==1 || (little(RYZ_ACTION(&parent->process,16)+8,8)&2))){
        memset(leader,0,sizeof(*leader));leader->vfork_parent=-1;
    }
}
static void exited(Jobs *jobs,Task *task)
{
    Task *leader=group_leader(jobs,task);
    futex_clear(task);
    robust_exit(jobs,task);
    if(task->cpu.tid_address && ryz_memory_access(task->cpu.m,task->cpu.tid_address,4,RYZ_WRITE)){
        memset(task->cpu.m->bytes+(size_t)(task->cpu.tid_address-task->cpu.m->base),0,4);
        futex_wake(jobs,task,task->cpu.tid_address,1,0xffffffffU);
    }
    ryz_world_close(&task->process,0);mm_release(jobs,task);task->state=ZOMBIE;release_vfork(jobs,task);
    finish_group(jobs,leader,task);
    if(task->thread){memset(task,0,sizeof(*task));task->vfork_parent=-1;}
}
static int process_admit(Jobs *jobs,Task *task)
{
    unsigned int i,count=0;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE)count++;
    return count<task->process.nproc_limit;
}
static int64_t fork_task(Jobs *jobs,Task *parent,int vfork)
{
    Task *child;unsigned int i;int memory_slot;unsigned char *bytes=NULL;
    if(!process_admit(jobs,parent) || jobs->forks>=RYZ_JOB_FORKS || parent->vfork_parent>=0)return -11;
    for(i=1;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state==FREE)break;
    if(i==RYZ_JOB_TASKS)return -11;
    memory_slot=vfork?(int)parent->mm:mm_free(jobs);if(memory_slot<0)return -12;
    if(!vfork){ryz_memory_commit(parent->cpu.m,1);bytes=arena_alloc(jobs,(size_t)parent->cpu.m->size);if(!bytes)return -12;memcpy(bytes,parent->cpu.m->bytes,(size_t)parent->cpu.m->size);}
    if(!vfork && !ryz_memory_fork(&jobs->memories[memory_slot].memory,parent->cpu.m,bytes)){arena_free(jobs,bytes,(size_t)parent->cpu.m->size);return -12;}
    child=&jobs->tasks[i];memset(child,0,sizeof(*child));child->vfork_parent=-1;
    child->process=parent->process;
    memcpy(child->process.signal_actions,RYZ_ACTION(&parent->process,0),sizeof child->process.signal_actions);
    child->process.fs_owner=NULL;child->process.action_owner=NULL;child->process.fd_owner=NULL;child->process.fd_shares=1;child->process.fd_detached=0;child->process.generated_signals=0;child->process.barrier_registered=0;
    child->alt_sp=parent->alt_sp;child->alt_size=parent->alt_size;child->signal_depth=parent->signal_depth;
    ryz_world_fork(&parent->process,&child->process);
    child->process.ns.pid=child->process.tgid=jobs->next_pid++;child->process.parent_pid=parent->process.tgid;
    child->cpu=parent->cpu;child->cpu.p=&child->process;child->cpu.r[0]=0;
    child->cpu.ip=parent->cpu.cur;child->cpu.r[1]=parent->cpu.cur;child->cpu.r[11]=parent->cpu.flags;child->cpu.tid_address=0;
    child->mm=(unsigned int)memory_slot;child->process.memory_index=child->mm;child->mm_held=1;
    if(vfork){child->vfork_parent=(int)(parent-jobs->tasks);child->vfork_parent_pid=parent->process.ns.pid;child->vfork_token=++parent->vfork_wait_token;parent->state=VFORK_WAIT;jobs->memories[child->mm].refs++;}
    else{
        MemorySlot *slot=&jobs->memories[child->mm];slot->used=slot->owned=1;slot->refs=1;
        slot->memory.process=&child->process;
        child->cpu.m=&slot->memory;child->process.guest_bytes=bytes;child->process.memory_context=&slot->memory;
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
        jobs->tasks[i].process.parent_pid==parent->process.tgid && !jobs->tasks[i].thread){
        Task *candidate=&jobs->tasks[i];
        if(wanted>0 && (uint64_t)wanted!=candidate->process.ns.pid)continue;
        if(wanted==0 && candidate->process.group_pid!=parent->process.group_pid)continue;
        if(wanted < -1 && (-(uint64_t)wanted)!=candidate->process.group_pid)continue;
        found=1;
        if((r->rdx&2) && candidate->stop_event){
            if(r->rsi)encode(parent->cpu.m->bytes+(size_t)(r->rsi-parent->cpu.m->base),((uint64_t)candidate->stop_event<<8)|127,4);
            candidate->stop_event=0;return candidate->process.ns.pid;
        }
        if((r->rdx&8) && candidate->continue_event){
            if(r->rsi)encode(parent->cpu.m->bytes+(size_t)(r->rsi-parent->cpu.m->base),65535,4);
            candidate->continue_event=0;return candidate->process.ns.pid;
        }
        if(candidate->state==ZOMBIE && !group_live(jobs,candidate->process.tgid)){child=candidate;break;}
    }
    if(!found)return -10;
    if(!child)return r->rdx&1?0:RYZ_LINUX_BLOCKED;
    wanted=child->process.ns.pid;
    if(r->rsi)encode(parent->cpu.m->bytes+(size_t)(r->rsi-parent->cpu.m->base),child->term_signal?(uint64_t)child->term_signal:(uint64_t)child->process.exit_status<<8,4);
    if(r->r10)memset(parent->cpu.m->bytes+(size_t)(r->r10-parent->cpu.m->base),0,144);
    memset(child,0,sizeof(*child));child->vfork_parent=-1;return wanted;
}
static int exec_task(Jobs *jobs,Task *task,const RyzLinuxRegs *r,int64_t *answer)
{
    ExecArgs *snapshot;RyzLinuxMemory *next;RyzVmResult *result=task->cpu.result;
    Task *replacement,*leader=group_leader(jobs,task);int moved=task!=leader;
    unsigned char *bytes;int memory_slot;char path[257];size_t i;uint64_t entry,stack;int status;const RyzLinuxExec *grant=NULL;
    if(result->execs>=RYZ_JOB_EXECS){*answer=-11;return RYZ_VM_OK;}
    {int trailing;status=ryz_linux_path(&task->process,(uint64_t)-100,r->rdi,path,1,&trailing);}
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
    bytes=arena_alloc(jobs,jobs->capacity);
    if(!bytes){free(snapshot);free(next);*answer=-12;return RYZ_VM_OK;}
    status=ryz_prepare_job(grant->image,grant->size,bytes,jobs->capacity,&snapshot->args,&jobs->world,next,&entry,&stack);
    free(snapshot);
    if(status!=RYZ_VM_OK){arena_free(jobs,bytes,jobs->capacity);free(next);*answer=-8;return RYZ_VM_OK;}
    {uint64_t mapped=0;for(i=0;i<next->size/RYZ_PAGE;i++)if(next->pages[i]&RYZ_MAP)mapped+=RYZ_PAGE;
     if(mapped>task->process.address_limit){arena_free(jobs,bytes,jobs->capacity);free(next);*answer=-12;return RYZ_VM_OK;}}
    memory_slot=jobs->memories[task->mm].refs==1?(int)task->mm:mm_free(jobs);
    if(memory_slot<0){arena_free(jobs,bytes,jobs->capacity);free(next);*answer=-12;return RYZ_VM_OK;}
    replacement=malloc(sizeof(*replacement));
    if(!replacement){arena_free(jobs,bytes,jobs->capacity);free(next);*answer=-12;return RYZ_VM_OK;}
    /* Keep the shared resource owner intact until the caller has detached. */
    for(i=0;i<RYZ_JOB_TASKS;i++)if(&jobs->tasks[i]!=task && jobs->tasks[i].state!=FREE && jobs->tasks[i].process.tgid==task->process.tgid){
        futex_clear(&jobs->tasks[i]);ryz_world_close(&jobs->tasks[i].process,0);mm_release(jobs,&jobs->tasks[i]);
    }
    futex_clear(task);
    ryz_world_close(&task->process,1);
    *replacement=*task;
    memcpy(replacement->process.signal_actions,RYZ_ACTION(&task->process,0),sizeof replacement->process.signal_actions);
    if(moved){
        memcpy(replacement->process_signals,leader->process_signals,sizeof replacement->process_signals);
        replacement->alarm_deadline=leader->alarm_deadline;replacement->alarm_interval=leader->alarm_interval;
        if(leader->signal_sequence>replacement->signal_sequence)replacement->signal_sequence=leader->signal_sequence;
    }
    replacement->vfork_wait_token=leader->vfork_wait_token+1;
    replacement->process.ns.pid=replacement->process.tgid;
    replacement->process.fd_owner=replacement->process.fs_owner=replacement->process.action_owner=NULL;
    replacement->process.fd_shares=1;replacement->process.fd_detached=0;
    ryz_resource_exec_view(&replacement->process,path);
    replacement->executed=1;replacement->thread=replacement->notified=0;replacement->leader=NULL;replacement->state=RUN;
    release_vfork(jobs,task);replacement->vfork_parent=-1;
    mm_release(jobs,task);
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.tgid==replacement->process.tgid){
        memset(&jobs->tasks[i],0,sizeof(Task));jobs->tasks[i].vfork_parent=-1;
    }
    *leader=*replacement;free(replacement);task=leader;
    task->mm=(unsigned int)memory_slot;task->process.memory_index=task->mm;task->mm_held=1;
    jobs->memories[task->mm].used=jobs->memories[task->mm].owned=1;jobs->memories[task->mm].refs=1;
    jobs->memories[task->mm].memory=*next;free(next);
    task->cpu.m=&jobs->memories[task->mm].memory;task->cpu.m->process=&task->process;
    task->process.guest_base=task->cpu.m->base;task->process.guest_bytes=bytes;task->process.guest_size=(size_t)task->cpu.m->size;
    task->process.memory_context=task->cpu.m;
    for(i=0;i<64;i++)if(little(RYZ_ACTION(&task->process,i),8)!=1)memset(RYZ_ACTION(&task->process,i),0,32);
    task->poll_active=0;task->process.barrier_registered=0;task->alt_sp=task->alt_size=0;task->signal_depth=0;task->sleep_kind=0;task->robust_head=0;task->futex_waiting=task->futex_woken=task->futex_restart.active=0;task->futex_deadline=0;task->blocked=task->suspended=0;
    memset(task->futex_frames,0,sizeof task->futex_frames);
    ryz_cpu_init(&task->cpu,&task->process,&jobs->memories[task->mm].memory,entry,stack,result);task->cpu.cur=entry;
    result->execs++;
    if(moved){result->syscall_count++;return RYZ_CPU_MOVED;}
    return RYZ_CPU_EXECUTED;
}
#include "jobs_threads.h"
#include "jobs_process.h"

static int job_call(void *context,void *cpu,const RyzLinuxRegs *r,int64_t *answer)
{
    Jobs *jobs=context;Task *task=NULL;unsigned int i;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(&jobs->tasks[i].cpu==cpu){task=&jobs->tasks[i];break;}
    if(!task)return RYZ_VM_BAD_INPUT;
    if(r->rax==97 || r->rax==160 || r->rax==302 || r->rax==109 || r->rax==112 || r->rax==121 || r->rax==124)return process_call(jobs,task,r,answer);
    if(r->rax==7){
        RyzLinuxRegs probe=*r;int32_t timeout=(int32_t)r->rdx;uint64_t now=jobs->world.clock;
        probe.rdx=0;*answer=ryz_linux_syscall(&task->process,&probe);
        if(*answer || !timeout){task->poll_active=0;return RYZ_VM_OK;}
        if(timeout>0){
            if(!task->poll_active){uint64_t duration=(uint64_t)timeout*1000;task->poll_deadline=duration>UINT64_MAX-now?UINT64_MAX:now+duration;task->poll_active=1;}
            if(now>=task->poll_deadline){task->poll_active=0;*answer=0;return RYZ_VM_OK;}
        }
        *answer=RYZ_LINUX_BLOCKED;return RYZ_CPU_BLOCKED;
    }
    if(r->rax==56 || r->rax==202 || r->rax==273 || r->rax==274 || r->rax==24 || r->rax==60 || r->rax==231)return thread_call(jobs,task,r,answer);
    if(r->rax==57 || r->rax==58)*answer=fork_task(jobs,task,r->rax==58);
    else if(r->rax==61)*answer=wait_task(jobs,task,r);
    else if(r->rax==59)return exec_task(jobs,task,r,answer);
    else if(r->rax==35 || r->rax==36 || r->rax==37 || r->rax==38 || r->rax==128 || r->rax==230)return timer_call(task,r,answer);
    else return signal_call(jobs,task,r,answer);
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
    Jobs *jobs;Task *root;uint64_t entry,stack;unsigned int i,j,q;size_t n,total_image_bytes;int status,progress;
    if(result)memset(result,0,sizeof(*result));
    if(config && config->filesystem){
        RyzFilesystemResources *fs=config->filesystem;fs->output_size=0;
        if((fs->input_size && !fs->input) || fs->input_size>RYZ_FS_SNAPSHOT_MAX || (fs->output && fs->output_capacity<RYZ_FS_SNAPSHOT_MAX) || (!fs->output && fs->output_capacity))return RYZ_VM_BAD_INPUT;
    }
    if(files){
        if(!files->input || !files->output || files->input_size>RYZ_LINUX_FILE_MAX ||
           files->output_capacity==0 || files->output_capacity>RYZ_LINUX_FILE_MAX)return RYZ_VM_BAD_INPUT;
        files->output_size=0;memset(files->output,0,files->output_capacity);
    }
    if(!result || !config || config->root_tree>1 || config->max_steps>16777216U || config->exec_count>RYZ_PROCESS_ARGS || (config->exec_count && !config->execs))return RYZ_VM_BAD_INPUT;
    if(config->network){
        const RyzNetworkResources *net=config->network;
        if(!net->count || net->count>RYZ_NETWORK_GRANTS || !net->grants || !net->now_ns || !net->wait || net->wall_milliseconds>10000)return RYZ_VM_BAD_INPUT;
        for(i=0;i<net->count;i++){
            const RyzNetworkGrant *g=&net->grants[i];const RyzNetworkOps *ops=g->ops;
            if(!g->address[0] || g->address[0]>=224 || !g->port || g->port>65535 || !ops || !ops->open || !ops->ready || !ops->read || !ops->write || !ops->close)return RYZ_VM_BAD_INPUT;
            for(j=0;j<i;j++)if(g->port==net->grants[j].port && !memcmp(g->address,net->grants[j].address,4))return RYZ_VM_BAD_INPUT;
        }
    }
    /* Account image buffers separately from the finite per-process arenas. */
    if(!image || length==0 || length>RYZ_PROCESS_IMAGE_MAX)return RYZ_VM_BAD_INPUT;
    total_image_bytes=length;
    for(i=0;i<config->exec_count;i++){
        if(!config->execs[i].path || config->execs[i].path[0]!='/')return RYZ_VM_BAD_INPUT;
        for(n=0;n<=256 && config->execs[i].path[n];n++);
        if(!valid_path(config->execs[i].path,n) || !config->execs[i].image || config->execs[i].size==0 || config->execs[i].size>RYZ_PROCESS_IMAGE_MAX ||
           config->execs[i].size>RYZ_PROCESS_IMAGE_TOTAL_MAX-total_image_bytes)return RYZ_VM_BAD_INPUT;
        total_image_bytes+=config->execs[i].size;
        for(j=0;j<i;j++)if(strcmp(config->execs[j].path,config->execs[i].path)==0)return RYZ_VM_BAD_INPUT;
    }
    result->instruction_limit=config->max_steps;
    jobs=malloc(sizeof(*jobs));if(!jobs)return RYZ_VM_BAD_INPUT;memset(jobs,0,sizeof(*jobs));
    for(i=0;i<RYZ_JOB_TASKS;i++)jobs->tasks[i].vfork_parent=-1;
    jobs->capacity=capacity<RYZ_PROCESS_MAX_SPAN?capacity:RYZ_PROCESS_MAX_SPAN;
    jobs->capacity &= ~(size_t)(RYZ_PAGE-1);
    jobs->arena_limit=config->arena_bytes_max?config->arena_bytes_max:9U*(uint64_t)RYZ_PROCESS_MAX_SPAN;
    if(jobs->arena_limit<jobs->capacity || jobs->arena_limit>9U*(uint64_t)RYZ_PROCESS_MAX_SPAN){free(jobs);return RYZ_VM_BAD_INPUT;}
    jobs->arena_bytes=jobs->arena_peak=jobs->capacity;
    jobs->next_pid=1001;jobs->world.execs=config->execs;jobs->world.exec_count=config->exec_count;jobs->world.random=config->random;jobs->world.random_context=config->random_context;
    jobs->world.root_tree=config->root_tree;
    if(config->filesystem && config->filesystem->input && !fs_import(&jobs->world,config->filesystem->input,config->filesystem->input_size)){free(jobs);return RYZ_VM_BAD_INPUT;}
    jobs->world.resources=config->resources;
    if(!ryz_resources_install(&jobs->world)){free(jobs);return RYZ_VM_BAD_INPUT;}
    jobs->world.network=config->network;
    if(config->network)jobs->world.network_start=jobs->world.network_last=config->network->now_ns(config->network->context);
    root=&jobs->tasks[0];root->mm_held=1;jobs->memories[0].used=1;jobs->memories[0].refs=1;root->cpu.m=&jobs->memories[0].memory;status=ryz_prepare_job(image,length,arena,capacity,args,&jobs->world,root->cpu.m,&entry,&stack);
    if(status!=RYZ_VM_OK){free(jobs);return status;}
    if(ryz_linux_process_init(&root->process,1,1000,1000,1000,root->cpu.m->base,arena,(size_t)root->cpu.m->size,output,opaque)!=0){free(jobs);return RYZ_VM_BAD_INPUT;}
    root->process.parent_pid=1;root->process.files=files;
    root->cpu.m->process=&root->process;root->process.memory_context=root->cpu.m;root->process.memory_read=ryz_memory_read;root->process.memory_write=ryz_memory_write;root->process.memory_call=ryz_memory_call;
    root->process.job_call=job_call;root->process.job_context=jobs;
    ryz_world_attach(&root->process,&jobs->world);ryz_resource_exec_view(&root->process,"@entry");root->state=RUN;result->peak_tasks=1;
    ryz_cpu_init(&root->cpu,&root->process,&jobs->memories[0].memory,entry,stack,result);
    status=RYZ_VM_OK;
    while(group_live(jobs,root->process.tgid)){
        if(!ryz_network_budget(&jobs->world)){status=RYZ_JOB_NETWORK_LIMIT;break;}
        progress=0;
        for(i=0;i<RYZ_JOB_TASKS && group_live(jobs,root->process.tgid);i++){
            Task *task=&jobs->tasks[i];
            if(task->state==FREE || task->state==ZOMBIE)continue;
            timer_poll(jobs,task);
            if(signal_deliver(jobs,task))progress=1;
            if(task->process.exited && task->state!=ZOMBIE){exited(jobs,task);progress=1;}
            if(task->state!=RUN)continue;
            for(q=0;q<RYZ_JOB_QUANTUM && task->state==RUN;q++){
                if((q&63)==0 && !ryz_network_budget(&jobs->world)){status=RYZ_JOB_NETWORK_LIMIT;goto done;}
                timer_poll(jobs,task);
                if(signal_deliver(jobs,task))progress=1;
                if(task->process.exited){exited(jobs,task);break;}
                if(task->state!=RUN)break;
                if(task->futex_restart.active && task->cpu.ip!=task->futex_restart.ip)task->futex_restart.active=0;
                task->cpu.m->process=&task->process;
                status=ryz_cpu_tick(&task->cpu);
                if(jobs->world.clock<UINT64_MAX)jobs->world.clock++;
                if(status==RYZ_CPU_MOVED){status=RYZ_VM_OK;progress=1;break;}
                if(status==RYZ_CPU_BLOCKED){task->blocked=1;result->blocked_syscalls++;status=RYZ_VM_OK;break;}
                if(status==RYZ_VM_MAP_ERROR && task->cpu.m->bus_valid){
                    SignalEvent event;uint64_t handler=little(RYZ_ACTION(&task->process,6),8);
                    memset(&event,0,sizeof(event));event.sig=7;event.code=2;event.address=task->cpu.m->bus_address;task->cpu.m->bus_valid=0;task->cpu.fault=0;
                    if(handler<=1 || (task->process.signal_mask & 64) || !signal_frame(task,&event))signal_fatal(jobs,task,7);
                    status=RYZ_VM_OK;
                }
                if(status!=RYZ_VM_OK)goto done;
                task->blocked=0;progress=1;
                if(task->process.exited){exited(jobs,task);break;}
                if(task->yielded){task->yielded=0;break;}
            }
        }
        if(!progress){
            int waiting=0;
            for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state==RUN && jobs->tasks[i].blocked)waiting=1;
            if(waiting && jobs->world.network){
                int idle=ryz_network_idle(&jobs->world);
                if(idle>0)continue;
                if(idle<0){status=RYZ_JOB_NETWORK_LIMIT;break;}
            }
            if(timer_advance(jobs))continue;
            status=RYZ_JOB_DEADLOCK;break;
        }
    }
    if(root->state==ZOMBIE){result->exited=1;result->exit_status=(uint8_t)(root->term_signal?128+root->term_signal:root->process.exit_status);}
 done:
    if(jobs->world.network_failed)status=RYZ_JOB_NETWORK_LIMIT;
    result->pipe_bytes=jobs->world.pipe_bytes;
    result->arena_peak_bytes=jobs->arena_peak;result->shared_peak_pages=jobs->world.shared_peak;
    /* Snapshot before closing descriptors/tearing down the guest world. */
    result->network_bytes=jobs->world.network_bytes;
    result->resource_bytes=jobs->world.resource_bytes;
    result->output_bytes=jobs->world.output_bytes;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE){futex_clear(&jobs->tasks[i]);ryz_world_close(&jobs->tasks[i].process,0);}
    for(i=0;i<RYZ_JOB_TASKS;i++)mm_release(jobs,&jobs->tasks[i]);
    if(config->filesystem && config->filesystem->output)fs_export(&jobs->world,config->filesystem);
    free(jobs);return status;
}
