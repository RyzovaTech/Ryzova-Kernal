/* SPDX-License-Identifier: AGPL-3.0-only */
/* Cooperative shared-mm threads. No native clone/futex/thread forwarding. */
static int futex_wake(Jobs *jobs,Task *caller,uint64_t address,uint32_t count,uint32_t mask)
{
    unsigned int i;uint32_t woke=0;
    for(i=0;i<RYZ_JOB_TASKS && woke<count;i++){
        Task *t=&jobs->tasks[i];
        if(t->state!=FREE && t->state!=ZOMBIE && t->cpu.m==caller->cpu.m && t->futex_waiting && t->futex_address==address && (t->futex_mask&mask)){
            t->futex_waiting=0;t->futex_woken=1;t->futex_deadline=0;woke++;
        }
    }
    return (int)woke;
}
static void robust_one(Jobs *jobs,Task *task,uint64_t node,int64_t offset)
{
    uint64_t at;uint32_t value;
    if(offset<0){if(node<-(uint64_t)offset)return;at=node-(-(uint64_t)offset);}
    else{if(node>UINT64_MAX-(uint64_t)offset)return;at=node+(uint64_t)offset;}
    if((at&3) || !ryz_memory_access(task->cpu.m,at,4,RYZ_READ|RYZ_WRITE))return;
    value=(uint32_t)little(task->cpu.m->bytes+(size_t)(at-task->cpu.m->base),4);
    if((value&0x3fffffffU)!=task->process.ns.pid)return;
    encode(task->cpu.m->bytes+(size_t)(at-task->cpu.m->base),(value&0x80000000U)|0x40000000U,4);
    if(value&0x80000000U)futex_wake(jobs,task,at,1,0xffffffffU);
}
static void robust_exit(Jobs *jobs,Task *task)
{
    uint64_t head=task->robust_head,node,next,pending;int64_t offset;unsigned int i;
    if(!head || !ryz_memory_access(task->cpu.m,head,24,RYZ_READ))return;
    node=little(task->cpu.m->bytes+(size_t)(head-task->cpu.m->base),8);
    offset=(int64_t)little(task->cpu.m->bytes+(size_t)(head-task->cpu.m->base)+8,8);
    pending=little(task->cpu.m->bytes+(size_t)(head-task->cpu.m->base)+16,8);
    for(i=0;i<2048 && (node&~UINT64_C(1))!=head && node;i++){
        uint64_t entry=node&~UINT64_C(1);
        if(!ryz_memory_access(task->cpu.m,entry,8,RYZ_READ))break;
        next=little(task->cpu.m->bytes+(size_t)(entry-task->cpu.m->base),8);
        if(!(node&1) && entry!=(pending&~UINT64_C(1)))robust_one(jobs,task,entry,offset);
        node=next;
    }
    if(pending && !(pending&1))robust_one(jobs,task,pending,offset);
}
static int64_t clone_thread(Jobs *jobs,Task *parent,const RyzLinuxRegs *r)
{
    const uint64_t required=0x10f00,allowed=0x17d0f00;
    Task *child,*leader;RyzLinuxProcess *fd_owner;unsigned int i;
    if(r->rdi==17 && r->rsi==0)return fork_task(jobs,parent,0);
    if((r->rdi & required)!=required || (r->rdi & ~allowed) || !r->rsi || (r->rsi&7))return -22;
    if(!ryz_memory_access(parent->cpu.m,r->rsi,8,RYZ_READ|RYZ_WRITE))return -14;
    if((r->rdi&0x100000) && !ryz_memory_access(parent->cpu.m,r->rdx,4,RYZ_WRITE))return -14;
    if((r->rdi&(0x200000|0x1000000)) && !ryz_memory_access(parent->cpu.m,r->r10,4,RYZ_WRITE))return -14;
    if((r->rdi&0x80000) && r->r8 && !ryz_memory_access(parent->cpu.m,r->r8,1,RYZ_READ))return -14;
    if(jobs->forks>=RYZ_JOB_FORKS || parent->vfork_parent>=0)return -11;
    for(i=1;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state==FREE)break;
    if(i==RYZ_JOB_TASKS)return -11;
    leader=group_leader(jobs,parent);child=&jobs->tasks[i];memset(child,0,sizeof(*child));
    child->vfork_parent=-1;child->mm=parent->mm;child->mm_held=1;jobs->memories[child->mm].refs++;child->thread=1;child->leader=leader;child->process=parent->process;child->process.fd_detached=0;
    ryz_world_fork(&parent->process,&child->process);
    fd_owner=parent->process.fd_owner?parent->process.fd_owner:&parent->process;fd_owner->fd_shares++;
    child->process.fd_owner=fd_owner;child->process.fd_shares=0;
    child->process.fs_owner=parent->process.fs_owner?parent->process.fs_owner:&parent->process;
    child->process.action_owner=parent->process.action_owner?parent->process.action_owner:&parent->process;
    child->process.generated_signals=0;child->process.exited=0;
    child->process.ns.pid=jobs->next_pid++;child->process.tgid=parent->process.tgid;
    child->cpu=parent->cpu;child->cpu.p=&child->process;child->cpu.r[0]=0;child->cpu.r[4]=r->rsi;
    child->cpu.ip=child->cpu.cur=parent->cpu.cur;child->cpu.r[1]=parent->cpu.cur;child->cpu.r[11]=parent->cpu.flags;
    if(r->rdi&0x80000)child->cpu.fsbase=r->r8;
    child->cpu.tid_address=(r->rdi&0x200000)?r->r10:0;
    if(r->rdi&0x100000)encode(parent->cpu.m->bytes+(size_t)(r->rdx-parent->cpu.m->base),child->process.ns.pid,4);
    if(r->rdi&0x1000000)encode(parent->cpu.m->bytes+(size_t)(r->r10-parent->cpu.m->base),child->process.ns.pid,4);
    child->state=RUN;jobs->forks++;parent->cpu.result->forks++;
    {unsigned int live=0;for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE)live++;
     if(live>parent->cpu.result->peak_tasks)parent->cpu.result->peak_tasks=live;}
    return (int64_t)child->process.ns.pid;
}
static int thread_call(Jobs *jobs,Task *task,const RyzLinuxRegs *r,int64_t *answer)
{
    RyzCpu *c=&task->cpu;uint64_t now=jobs->world.clock,at=r->rdi,duration=0;uint32_t operation=(uint32_t)r->rsi,command=operation&127,mask=0xffffffffU,value;int error;
    if(r->rax==56){*answer=clone_thread(jobs,task,r);return RYZ_VM_OK;}
    if(r->rax==60 || r->rax==231){
        if(r->rax==231)group_exit(jobs,task,0,(unsigned int)r->rdi);
        else{task->process.exited=1;task->process.exit_status=(uint8_t)r->rdi;}
        *answer=0;return RYZ_VM_OK;
    }
    if(r->rax==24){task->yielded=1;*answer=0;return RYZ_VM_OK;}
    if(r->rax==273){
        if(r->rsi!=24){*answer=-22;return RYZ_VM_OK;}
        if(r->rdi && !ryz_memory_access(c->m,r->rdi,24,RYZ_READ)){*answer=-14;return RYZ_VM_OK;}
        task->robust_head=r->rdi;*answer=0;return RYZ_VM_OK;
    }
    if(r->rax==274){
        Task *other=task;unsigned int i;
        if(r->rdi)for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.ns.pid==(uint32_t)r->rdi){other=&jobs->tasks[i];break;}
        if(r->rdi && other==task && r->rdi!=task->process.ns.pid){*answer=-3;return RYZ_VM_OK;}
        if(!ryz_memory_access(c->m,r->rsi,8,RYZ_WRITE) || !ryz_memory_access(c->m,r->rdx,8,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
        encode(c->m->bytes+(size_t)(r->rsi-c->m->base),other->robust_head,8);encode(c->m->bytes+(size_t)(r->rdx-c->m->base),24,8);*answer=0;return RYZ_VM_OK;
    }
    if((operation & ~(uint32_t)(127|128|256)) || (command!=0 && command!=1 && command!=3 && command!=4 && command!=9 && command!=10) || ((operation&256) && command!=9)){*answer=-38;return RYZ_VM_OK;}
    if((command==0 || command==9) && task->futex_woken){task->futex_woken=0;*answer=0;return RYZ_VM_OK;}
    if((at&3) || !ryz_memory_access(c->m,at,4,RYZ_READ)){*answer=(at&3)?-22:-14;return RYZ_VM_OK;}
    if(command==3 || command==4){
        unsigned int i;uint32_t moved=0;int woke;
        if((r->r8&3) || !ryz_memory_access(c->m,r->r8,4,RYZ_READ)){*answer=(r->r8&3)?-22:-14;return RYZ_VM_OK;}
        if((int32_t)r->rdx<0 || (int32_t)r->r10<0){*answer=-22;return RYZ_VM_OK;}
        if(command==4 && little(c->m->bytes+(size_t)(at-c->m->base),4)!=(uint32_t)r->r9){*answer=-11;return RYZ_VM_OK;}
        woke=futex_wake(jobs,task,at,(uint32_t)r->rdx,0xffffffffU);
        for(i=0;i<RYZ_JOB_TASKS && moved<(uint32_t)r->r10;i++){
            Task *other=&jobs->tasks[i];
            if(other->state!=FREE && other->futex_waiting && other->cpu.m==c->m && other->futex_address==at){other->futex_address=r->r8;moved++;}
        }
        *answer=woke+moved;return RYZ_VM_OK;
    }
    if(command==9 || command==10){mask=(uint32_t)r->r9;if(!mask){*answer=-22;return RYZ_VM_OK;}}
    if(command==1 || command==10){uint32_t count=(int32_t)r->rdx<=0?1:(uint32_t)r->rdx;*answer=futex_wake(jobs,task,at,count,mask);return RYZ_VM_OK;}
        if(!task->futex_waiting){
        value=(uint32_t)little(c->m->bytes+(size_t)(at-c->m->base),4);
        if(value!=(uint32_t)r->rdx){*answer=-11;return RYZ_VM_OK;}
        if(task->futex_restart.active && task->futex_restart.ip==c->ip && task->futex_restart.address==at){
            task->futex_deadline=task->futex_restart.deadline;task->futex_restart.active=0;
        }else{
            if(r->r10){error=timer_duration(c,r->r10,0,&duration);if(error || (command==0 && duration>UINT64_MAX-now)){*answer=error?error:-22;return RYZ_VM_OK;}}
            task->futex_deadline=r->r10?(command==9?duration:now+duration):0;
        }
        task->futex_waiting=1;task->futex_address=at;task->futex_mask=mask;
    }
    if(r->r10 && now>=task->futex_deadline){task->futex_waiting=0;task->futex_deadline=0;*answer=-110;return RYZ_VM_OK;}
    *answer=RYZ_LINUX_BLOCKED;return RYZ_CPU_BLOCKED;
}
