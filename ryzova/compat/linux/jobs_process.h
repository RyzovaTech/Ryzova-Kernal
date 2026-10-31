/* SPDX-License-Identifier: AGPL-3.0-only */
/* Namespace-local process groups/sessions and enforced bounded resource limits. */
static Task *process_find(Jobs *jobs,Task *caller,uint64_t pid)
{
    unsigned int i;if(!pid)pid=caller->process.tgid;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.ns.pid==pid && jobs->tasks[i].process.tgid==pid)return &jobs->tasks[i];
    return NULL;
}
static int process_call(Jobs *jobs,Task *task,const RyzLinuxRegs *r,int64_t *answer)
{
    Task *target;RyzLinuxProcess *p=&task->process;unsigned int i;uint64_t group,resource,new_at,old_at,soft,hard,cap,a,b;int error=0,found=0;
    if(r->rax==97 || r->rax==160 || r->rax==302){
        target=r->rax==302?process_find(jobs,task,r->rdi):group_leader(jobs,task);
        if(!target){*answer=-3;return RYZ_VM_OK;}
        resource=r->rax==302?r->rsi:r->rdi;new_at=r->rax==97?0:(r->rax==302?r->rdx:r->rsi);old_at=r->rax==160?0:(r->rax==302?r->r10:r->rsi);
        p=&target->process;
        switch(resource){
        case 7:soft=p->file_limit;hard=p->file_hard;cap=RYZ_LINUX_FD_MAX;break;
        case 6:soft=p->nproc_limit;hard=p->nproc_hard;cap=RYZ_JOB_TASKS;break;
        case 9:soft=p->address_limit;hard=p->address_hard;cap=RYZ_PROCESS_MAX_SPAN;break;
        case 3:soft=hard=cap=RYZ_PROCESS_STACK;break;
        case 4:soft=hard=cap=0;break;
        default:*answer=-22;return RYZ_VM_OK;
        }
        /* Read input before update; Linux prlimit updates even if old-limit copyout faults. */
        a=soft;b=hard;
        if(new_at){
            if(!ryz_memory_access(task->cpu.m,new_at,16,RYZ_READ))error=-14;
            else{a=little(task->cpu.m->bytes+(size_t)(new_at-task->cpu.m->base),8);b=little(task->cpu.m->bytes+(size_t)(new_at-task->cpu.m->base)+8,8);if(a>b)error=-22;else if(b>hard || b>cap)error=-1;else if((resource==3 || resource==4) && (a!=soft || b!=hard))error=-95;}
        }
        if(error){*answer=error;return RYZ_VM_OK;}
        if(new_at)for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.tgid==p->tgid){
            RyzLinuxProcess *q=&jobs->tasks[i].process;
            if(resource==7){q->file_limit=(unsigned int)a;q->file_hard=(unsigned int)b;}
            if(resource==6){q->nproc_limit=(unsigned int)a;q->nproc_hard=(unsigned int)b;}
            if(resource==9){q->address_limit=a;q->address_hard=b;}
        }
        if(old_at && !ryz_memory_access(task->cpu.m,old_at,16,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
        if(old_at){encode(task->cpu.m->bytes+(size_t)(old_at-task->cpu.m->base),soft,8);encode(task->cpu.m->bytes+(size_t)(old_at-task->cpu.m->base)+8,hard,8);}
        *answer=0;return RYZ_VM_OK;
    }
    if(r->rax==109 && ((int32_t)r->rdi<0 || (int32_t)r->rsi<0)){*answer=-22;return RYZ_VM_OK;}
    target=process_find(jobs,task,r->rax==112?0:r->rdi);
    if(!target){*answer=-3;return RYZ_VM_OK;}
    if(r->rax==121 || r->rax==124){*answer=r->rax==121?target->process.group_pid:target->process.session_pid;return RYZ_VM_OK;}
    if(r->rax==112){
        for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.group_pid==p->tgid)found=1;
        if(found){*answer=-1;return RYZ_VM_OK;}
        group=p->tgid;
    }else{
        if((int32_t)r->rdi<0 || (int32_t)r->rsi<0){*answer=-22;return RYZ_VM_OK;}
        if(target->process.tgid!=p->tgid && target->process.parent_pid!=p->tgid){*answer=-3;return RYZ_VM_OK;}
        if(target->process.tgid!=p->tgid && target->executed){*answer=-13;return RYZ_VM_OK;}
        if(target->process.session_pid!=p->session_pid || target->process.session_pid==target->process.tgid){*answer=-1;return RYZ_VM_OK;}
        group=r->rsi?r->rsi:target->process.tgid;
        if(group!=target->process.tgid){
            for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.group_pid==group && jobs->tasks[i].process.session_pid==p->session_pid)found=1;
            if(!found){*answer=-1;return RYZ_VM_OK;}
        }
    }
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE && jobs->tasks[i].process.tgid==target->process.tgid){jobs->tasks[i].process.group_pid=(uint32_t)group;if(r->rax==112)jobs->tasks[i].process.session_pid=(uint32_t)group;}
    *answer=r->rax==112?(int64_t)group:0;return RYZ_VM_OK;
}
