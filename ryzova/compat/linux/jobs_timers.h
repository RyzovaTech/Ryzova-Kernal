/* SPDX-License-Identifier: AGPL-3.0-only */
/* Invocation-local logical time: one microsecond per guest instruction, and
 * deterministic advancement to the next deadline when every task blocks. */
static int timer_duration(RyzCpu *c,uint64_t at,int timeval,uint64_t *out)
{
    uint64_t sec,sub;
    if(!ryz_memory_access(c->m,at,16,RYZ_READ))return -14;
    sec=little(c->m->bytes+(size_t)(at-c->m->base),8);sub=little(c->m->bytes+(size_t)(at-c->m->base)+8,8);
    if(sec>UINT64_MAX/1000000 || sub>=(timeval?1000000U:1000000000U))return -22;
    sub=timeval?sub:(sub+999)/1000;
    if(sec*1000000>UINT64_MAX-sub)return -22;
    *out=sec*1000000+sub;return 0;
}
static void timer_write(Task *task,uint64_t at,uint64_t value,int timeval)
{
    unsigned char *b=task->cpu.m->bytes+(size_t)(at-task->cpu.m->base);
    encode(b,value/1000000,8);encode(b+8,(value%1000000)*(timeval?1:1000),8);
}
static int timer_interrupt(Task *task)
{
    int error=4;
    if(task->sleep_kind==1 && task->sleep_remaining){
        uint64_t now=task->process.world->clock,left=task->sleep_deadline>now?task->sleep_deadline-now:0;
        if(!ryz_memory_access(task->cpu.m,task->sleep_remaining,16,RYZ_WRITE))error=14;
        else timer_write(task,task->sleep_remaining,left,0);
    }
    task->sleep_kind=0;task->sleep_deadline=task->sleep_remaining=0;return error;
}
static void timer_poll(Jobs *jobs,Task *task)
{
    uint64_t now=jobs->world.clock,next;
    if(task->alarm_deadline && now>=task->alarm_deadline){
        signal_queue(jobs,task,14,task->process.ns.pid,128,0);
        if(!task->alarm_interval)task->alarm_deadline=0;
        else{
            next=task->alarm_interval-(now-task->alarm_deadline)%task->alarm_interval;
            task->alarm_deadline=now<=UINT64_MAX-next?now+next:0;
        }
    }
}
static int timer_advance(Jobs *jobs)
{
    unsigned int i;uint64_t next=UINT64_MAX;int found=0;
    for(i=0;i<RYZ_JOB_TASKS;i++){
        Task *t=&jobs->tasks[i];if(t->state==FREE || t->state==ZOMBIE)continue;
        if(t->alarm_deadline && (!found || t->alarm_deadline<next)){next=t->alarm_deadline;found=1;}
        if(t->state==RUN && t->sleep_kind && t->sleep_deadline && (!found || t->sleep_deadline<next)){next=t->sleep_deadline;found=1;}
    }
    if(!found || next<=jobs->world.clock)return 0;
    jobs->world.clock=next;return 1;
}
static int timer_call(Task *task,const RyzLinuxRegs *r,int64_t *answer)
{
    RyzCpu *c=&task->cpu;uint64_t now=task->process.world->clock,duration=0,interval=0,remaining=0,at,rem,mask;
    unsigned int i,chosen=64;int error;unsigned char *b;
    if(r->rax==37){
        remaining=task->alarm_deadline>now?task->alarm_deadline-now:0;
        remaining=remaining/1000000+(remaining%1000000!=0);
        if(remaining>UINT64_C(0xffffffff))remaining=UINT64_C(0xffffffff);
        duration=(uint64_t)(uint32_t)r->rdi*1000000;
        if(duration>UINT64_MAX-now){*answer=-22;return RYZ_VM_OK;}
        task->alarm_deadline=duration?now+duration:0;task->alarm_interval=0;*answer=(int64_t)remaining;return RYZ_VM_OK;
    }
    if(r->rax==36 || r->rax==38){
        if(r->rdi!=0){*answer=-22;return RYZ_VM_OK;}
        at=r->rax==36?r->rsi:r->rdx;
        if(r->rax==38){
            error=timer_duration(c,r->rsi,1,&interval);if(!error)error=timer_duration(c,r->rsi+16,1,&duration);
            if(error || duration>UINT64_MAX-now){*answer=error?error:-22;return RYZ_VM_OK;}
        }
        if(at){
            if(!ryz_memory_access(c->m,at,32,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
            timer_write(task,at,task->alarm_interval,1);timer_write(task,at+16,task->alarm_deadline>now?task->alarm_deadline-now:0,1);
        }else if(r->rax==36){*answer=-14;return RYZ_VM_OK;}
        if(r->rax==38){task->alarm_interval=interval;task->alarm_deadline=duration?now+duration:0;}
        *answer=0;return RYZ_VM_OK;
    }
    if(r->rax==128){
        if(r->r10!=8){*answer=-22;return RYZ_VM_OK;}
        if(!ryz_memory_access(c->m,r->rdi,8,RYZ_READ) || (r->rsi && !ryz_memory_access(c->m,r->rsi,128,RYZ_WRITE))){*answer=-14;return RYZ_VM_OK;}
        mask=little(c->m->bytes+(size_t)(r->rdi-c->m->base),8)&~SIG_UNBLOCKABLE;
        for(i=0;i<64;i++)if(task->signals[i].sig && ((mask>>(task->signals[i].sig-1))&1) &&
            (chosen==64 || task->signals[i].sig<task->signals[chosen].sig || (task->signals[i].sig==task->signals[chosen].sig && task->signals[i].sequence<task->signals[chosen].sequence)))chosen=i;
        if(chosen!=64){
            SignalEvent *e=&task->signals[chosen];*answer=e->sig;
            if(r->rsi){b=c->m->bytes+(size_t)(r->rsi-c->m->base);memset(b,0,128);encode(b,e->sig,4);encode(b+8,(uint32_t)e->code,4);encode(b+16,e->pid,4);encode(b+20,e->uid,4);if(e->sig==17)encode(b+24,(uint32_t)e->status,4);}
            e->sig=0;task->sleep_kind=0;return RYZ_VM_OK;
        }
        if(!task->sleep_kind){
            if(r->rdx){error=timer_duration(c,r->rdx,0,&duration);if(error || duration>UINT64_MAX-now){*answer=error?error:-22;return RYZ_VM_OK;}}
            task->sleep_kind=2;task->sleep_deadline=r->rdx?now+duration:0;
        }
        if(r->rdx && now>=task->sleep_deadline){task->sleep_kind=0;*answer=-11;return RYZ_VM_OK;}
        *answer=RYZ_LINUX_BLOCKED;return RYZ_CPU_BLOCKED;
    }
    at=r->rax==35?r->rdi:r->rdx;rem=r->rax==35?r->rsi:r->r10;
    if(r->rax==230 && ((r->rdi!=0 && r->rdi!=1 && r->rdi!=7) || r->rsi>1)){*answer=-22;return RYZ_VM_OK;}
    if(!task->sleep_kind){
        error=timer_duration(c,at,0,&duration);if(error){*answer=error;return RYZ_VM_OK;}
        if(rem && !(r->rax==230 && r->rsi==1) && !ryz_memory_access(c->m,rem,16,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
        if(r->rax!=230 || r->rsi==0){if(duration>UINT64_MAX-now){*answer=-22;return RYZ_VM_OK;}duration+=now;}
        task->sleep_kind=1;task->sleep_deadline=duration;task->sleep_remaining=r->rax==230 && r->rsi==1?0:rem;
    }
    if(now>=task->sleep_deadline){task->sleep_kind=0;task->sleep_remaining=0;*answer=0;return RYZ_VM_OK;}
    *answer=RYZ_LINUX_BLOCKED;return RYZ_CPU_BLOCKED;
}
