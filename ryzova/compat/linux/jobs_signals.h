/* SPDX-License-Identifier: AGPL-3.0-only */
/* Internal guest-only AMD64 Linux signal ABI. No host signal handlers. */
#define SIG_UNBLOCKABLE ((UINT64_C(1)<<8)|(UINT64_C(1)<<18))
#define SIG_RESTART UINT64_C(0x10000000)
#define SIG_RESTORER UINT64_C(0x04000000)
#define SIG_ONSTACK UINT64_C(0x08000000)
static Task *task_parent(Jobs *jobs,Task *task)
{
    unsigned int i;
    for(i=0;i<RYZ_JOB_TASKS;i++)if(jobs->tasks[i].state!=FREE &&
        jobs->tasks[i].process.ns.pid==task->process.parent_pid)return &jobs->tasks[i];
    return NULL;
}
static int signal_ignored(Task *task,unsigned int sig)
{
    uint64_t handler=little(task->process.signal_actions[sig-1],8);
    return handler==1 || (handler==0 && (sig==17 || sig==18 || sig==23 || sig==28));
}
static void child_notification(Jobs *,Task *,int,int);
static int signal_queue(Jobs *jobs,Task *task,unsigned int sig,unsigned int pid,int code,int value)
{
    SignalEvent *e=NULL;unsigned int i;
    if(sig==18){
        for(i=0;i<64;i++)if(task->signals[i].sig>=19 && task->signals[i].sig<=22)task->signals[i].sig=0;
        if(task->state==STOPPED){task->state=RUN;task->stop_event=0;task->continue_event=1;child_notification(jobs,task,6,18);}
    }
    if(sig>=19 && sig<=22)for(i=0;i<64;i++)if(task->signals[i].sig==18)task->signals[i].sig=0;
    if(signal_ignored(task,sig) && sig!=9 && sig!=19)return 0;
    if(sig<=31){e=&task->signals[sig-1];if(e->sig)return 0;}
    else{
        for(i=31;i<64;i++)if(!task->signals[i].sig){e=&task->signals[i];break;}
        if(!e)return -11;
    }
    memset(e,0,sizeof(*e));e->sig=sig;e->pid=pid;e->uid=task->process.ns.uid;e->code=code;e->status=value;
    e->sequence=++task->signal_sequence;return 0;
}
static void child_notification(Jobs *jobs,Task *task,int code,int status)
{
    Task *parent=task_parent(jobs,task);
    if(!parent)return;
    if((code==5 || code==6) && (little(parent->process.signal_actions[16]+8,8)&1))return;
    signal_queue(jobs,parent,17,task->process.ns.pid,code,status);
}
static uint64_t signal_pending(Task *task)
{
    unsigned int i;uint64_t pending=0;
    for(i=0;i<64;i++)if(task->signals[i].sig)pending|=UINT64_C(1)<<(task->signals[i].sig-1);
    return pending;
}
static void signal_fatal(Task *task,unsigned int sig)
{
    task->term_signal=(int)sig;task->process.exited=1;
}
static int on_altstack(Task *task,uint64_t sp)
{
    return task->alt_size && sp>=task->alt_sp && sp-task->alt_sp<task->alt_size;
}
/* Linux UAPI rt_sigframe: return address, 304-byte ucontext, 128-byte siginfo.
 * sigcontext is at frame+48. FXSAVE state is separately aligned after info. */
static int signal_frame(Task *task,SignalEvent *event)
{
    static const unsigned char registers[16]={8,9,10,11,12,13,14,15,7,6,5,3,2,0,1,4};
    RyzCpu *c=&task->cpu;unsigned char *b,*sc,*info,*fpbytes;
    uint64_t handler,flags,restorer,top,fp,sp,mask,save_mask;unsigned int i;
    handler=little(task->process.signal_actions[event->sig-1],8);
    flags=little(task->process.signal_actions[event->sig-1]+8,8);
    restorer=little(task->process.signal_actions[event->sig-1]+16,8);
    mask=little(task->process.signal_actions[event->sig-1]+24,8);
    if(task->signal_depth>=8 || !(flags&SIG_RESTORER) || !ryz_memory_access(c->m,handler,1,RYZ_EXEC) ||
        !ryz_memory_access(c->m,restorer,1,RYZ_EXEC))return 0;
    top=c->r[4];
    if((flags&SIG_ONSTACK) && task->alt_size && !on_altstack(task,top))top=task->alt_sp+task->alt_size;
    else{if(top<128)return 0;top-=128;}
    if(top<1024)return 0;
    fp=(top-512)&~UINT64_C(63);sp=((fp-440)&~UINT64_C(15))-8;
    if(!ryz_memory_access(c->m,sp,top-sp,RYZ_WRITE))return 0;
    if((flags&SIG_ONSTACK) && on_altstack(task,top-1) && sp<task->alt_sp)return 0;
    save_mask=task->suspended?task->suspend_mask:task->process.signal_mask;
    if(task->blocked){
        c->r[1]=c->cur;c->r[11]=c->flags;
        if(task->suspended || task->sleep_kind || !(flags&SIG_RESTART) || c->r[0]==7){int error=timer_interrupt(task);c->ip=c->cur;c->r[0]=(uint64_t)-(int64_t)error;}
        task->blocked=0;
    }
    task->suspended=0;
    b=c->m->bytes+(size_t)(sp-c->m->base);memset(b,0,(size_t)(top-sp));
    encode(b,restorer,8);encode(b+8,6,8);
    encode(b+24,task->alt_sp,8);encode(b+32,task->alt_size?(on_altstack(task,c->r[4])?1:0):2,4);encode(b+40,task->alt_size,8);
    sc=b+48;for(i=0;i<16;i++)encode(sc+i*8,c->r[registers[i]],8);
    encode(sc+128,c->ip,8);encode(sc+136,c->flags,8);encode(sc+144,0x33,2);encode(sc+150,0x2b,2);
    encode(sc+168,save_mask,8);encode(sc+184,fp,8);encode(b+304,save_mask,8);
    info=b+312;encode(info,event->sig,4);encode(info+8,(uint32_t)event->code,4);encode(info+16,event->pid,4);encode(info+20,event->uid,4);
    if(event->sig==17)encode(info+24,(uint32_t)event->status,4);
    fpbytes=c->m->bytes+(size_t)(fp-c->m->base);encode(fpbytes,0x37f,2);encode(fpbytes+24,0x1f80,4);encode(fpbytes+28,0xffff,4);
    memcpy(fpbytes+160,c->xmm,sizeof c->xmm);
    task->process.signal_mask|=mask;
    if(!(flags&UINT64_C(0x40000000)))task->process.signal_mask|=UINT64_C(1)<<(event->sig-1);
    task->process.signal_mask&=~SIG_UNBLOCKABLE;
    if(flags&UINT64_C(0x80000000))memset(task->process.signal_actions[event->sig-1],0,32);
    c->r[4]=sp;c->r[7]=event->sig;c->r[6]=sp+312;c->r[2]=sp+8;c->r[0]=0;c->ip=c->cur=handler;
    c->flags&=~UINT64_C(0x500);task->signal_depth++;return 1;
}
static int signal_deliver(Jobs *jobs,Task *task)
{
    unsigned int i,chosen=64,sig;uint64_t generated=task->process.generated_signals;
    SignalEvent event;
    task->process.generated_signals=0;
    for(i=0;i<64;i++)if((generated>>i)&1)signal_queue(jobs,task,i+1,task->process.ns.pid,0,0);
    for(i=0;i<64;i++)if(task->signals[i].sig){
        sig=task->signals[i].sig;
        if(signal_ignored(task,sig) && sig!=9 && sig!=19){task->signals[i].sig=0;continue;}
        if(sig!=9 && sig!=19 && ((task->process.signal_mask>>(sig-1))&1))continue;
        if(task->state==VFORK_WAIT && sig!=9)continue;
        if(task->state==STOPPED && sig!=9 && sig!=18)continue;
        if(chosen==64 || sig==9 || (task->signals[chosen].sig!=9 &&
           (sig<task->signals[chosen].sig || (sig==task->signals[chosen].sig && task->signals[i].sequence<task->signals[chosen].sequence))))chosen=i;
    }
    if(chosen==64)return 0;
    event=task->signals[chosen];task->signals[chosen].sig=0;sig=event.sig;
    if(signal_ignored(task,sig) && sig!=9 && sig!=19)return 1;
    if(sig==9){signal_fatal(task,sig);return 1;}
    if(sig==19 || (little(task->process.signal_actions[sig-1],8)==0 && sig>=20 && sig<=22)){
        task->state=STOPPED;task->stop_event=(int)sig;task->continue_event=0;child_notification(jobs,task,5,(int)sig);return 1;
    }
    if(little(task->process.signal_actions[sig-1],8)==0 || !signal_frame(task,&event))signal_fatal(task,little(task->process.signal_actions[sig-1],8)==0?sig:11);
    return 1;
}
static int signal_return(Task *task)
{
    static const unsigned char registers[16]={8,9,10,11,12,13,14,15,7,6,5,3,2,0,1,4};
    RyzCpu *c=&task->cpu;unsigned char *b,*sc,*fpu=NULL;uint64_t sp,ip,stack,fp,mask,flags,values[16],alt,alt_size,alt_flags;unsigned int i;
    if(c->r[4]<8)return 0;
    sp=c->r[4]-8;
    if(!ryz_memory_access(c->m,sp,440,RYZ_READ))return 0;
    b=c->m->bytes+(size_t)(sp-c->m->base);sc=b+48;
    alt=little(b+24,8);alt_flags=little(b+32,4);alt_size=little(b+40,8);
    if(alt_flags>2 || (alt_flags!=2 && (alt_size<2048 || !ryz_memory_access(c->m,alt,alt_size,RYZ_WRITE))))return 0;
    ip=little(sc+128,8);stack=little(sc+120,8);fp=little(sc+184,8);mask=little(b+304,8);flags=little(sc+136,8);
    if(little(sc+144,2)!=0x33 || little(sc+150,2)!=0x2b || !ryz_memory_access(c->m,ip,1,RYZ_EXEC) ||
        !ryz_memory_access(c->m,stack,0,RYZ_READ))return 0;
    if(fp){if((fp&15) || !ryz_memory_access(c->m,fp,512,RYZ_READ))return 0;fpu=c->m->bytes+(size_t)(fp-c->m->base);if(little(fpu+24,4)&~UINT64_C(0xffff))return 0;}
    for(i=0;i<16;i++)values[i]=little(sc+i*8,8);
    for(i=0;i<16;i++)c->r[registers[i]]=values[i];
    c->ip=c->cur=ip;c->flags=(flags&UINT64_C(0x250dd5))|0x202;c->fault=0;
    if(fpu)memcpy(c->xmm,fpu+160,sizeof c->xmm);
    task->alt_sp=alt_flags==2?0:alt;task->alt_size=alt_flags==2?0:alt_size;
    task->process.signal_mask=mask&~SIG_UNBLOCKABLE;
    if(task->signal_depth)task->signal_depth--;
    return 1;
}
static int signal_call(Jobs *jobs,Task *task,const RyzLinuxRegs *r,int64_t *answer)
{
    unsigned int i,sig;int found=0,code=0;uint64_t mask;unsigned char *b;RyzCpu *c=&task->cpu;
    if(r->rax==15){if(!signal_return(task))signal_fatal(task,11);return RYZ_CPU_EXECUTED;}
    if(r->rax==62 || r->rax==200 || r->rax==234){
        int64_t pid=(int32_t)r->rdi;
        sig=(uint32_t)(r->rax==234?r->rdx:r->rsi);
        if(sig>64){*answer=-22;return RYZ_VM_OK;}
        for(i=0;i<RYZ_JOB_TASKS;i++){
            Task *target=&jobs->tasks[i];int matches;
            if(target->state==FREE)continue;
            if(r->rax==234)matches=(uint32_t)r->rdi==target->process.ns.pid && (uint32_t)r->rsi==target->process.ns.pid;
            else if(r->rax==200)matches=(uint32_t)pid==target->process.ns.pid;
            else matches=pid>0?(uint32_t)pid==target->process.ns.pid:(pid==0?target->process.group_pid==task->process.group_pid:(pid==-1?target!=task:target->process.group_pid==-(uint64_t)pid));
            if(!matches)continue;
            found=1;if(sig && target->state!=ZOMBIE){int error=signal_queue(jobs,target,sig,task->process.ns.pid,r->rax==62?0:-6,0);if(error)code=error;}
        }
        *answer=!found?-3:code;return RYZ_VM_OK;
    }
    if(r->rax==127){
        if(r->rsi!=8){*answer=-22;return RYZ_VM_OK;}
        if(!ryz_memory_access(c->m,r->rdi,8,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
        encode(c->m->bytes+(size_t)(r->rdi-c->m->base),signal_pending(task)&task->process.signal_mask,8);*answer=0;return RYZ_VM_OK;
    }
    if(r->rax==34 || r->rax==130){
        if(!task->suspended){
            mask=task->process.signal_mask;
            if(r->rax==130){
                if(r->rsi!=8){*answer=-22;return RYZ_VM_OK;}
                if(!ryz_memory_access(c->m,r->rdi,8,RYZ_READ)){*answer=-14;return RYZ_VM_OK;}
                mask=little(c->m->bytes+(size_t)(r->rdi-c->m->base),8)&~SIG_UNBLOCKABLE;
            }
            task->suspend_mask=task->process.signal_mask;task->process.signal_mask=mask;task->suspended=1;
        }
        *answer=RYZ_LINUX_BLOCKED;return RYZ_CPU_BLOCKED;
    }
    if(r->rax==131){
        uint64_t base=task->alt_sp,size=task->alt_size,flags=0;unsigned char snapshot[24];
        if(r->rdi){
            if(!ryz_memory_access(c->m,r->rdi,24,RYZ_READ)){*answer=-14;return RYZ_VM_OK;}
            memcpy(snapshot,c->m->bytes+(size_t)(r->rdi-c->m->base),24);base=little(snapshot,8);flags=little(snapshot+8,4);size=little(snapshot+16,8);
            if(on_altstack(task,c->r[4])){*answer=-1;return RYZ_VM_OK;}
            if(flags!=0 && flags!=2){*answer=-22;return RYZ_VM_OK;}
            if(flags!=2 && size<2048){*answer=-12;return RYZ_VM_OK;}
            if(flags!=2 && !ryz_memory_access(c->m,base,size,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
        }
        if(r->rsi){
            if(!ryz_memory_access(c->m,r->rsi,24,RYZ_WRITE)){*answer=-14;return RYZ_VM_OK;}
            b=c->m->bytes+(size_t)(r->rsi-c->m->base);memset(b,0,24);encode(b,task->alt_sp,8);encode(b+8,task->alt_size?(on_altstack(task,c->r[4])?1:0):2,4);encode(b+16,task->alt_size,8);
        }
        if(r->rdi){task->alt_sp=flags==2?0:base;task->alt_size=flags==2?0:size;}
        *answer=0;return RYZ_VM_OK;
    }
    *answer=-38;return RYZ_VM_OK;
}
