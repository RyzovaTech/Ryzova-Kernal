/* SPDX-License-Identifier: AGPL-3.0-only */
/* Queue keys retain shared backing objects, independently of current VA/maps. */
static int futex_equal(const RyzFutexKey *a,const RyzFutexKey *b)
{return a->kind==b->kind && a->memory==b->memory && a->identity==b->identity && a->offset==b->offset;}
static void futex_clear(Task *task)
{
    if(task->futex_waiting)ryz_memory_key_ref(task->process.world,&task->futex_key,-1);
    task->futex_waiting=0;memset(&task->futex_key,0,sizeof task->futex_key);
}
static int futex_wake_key(Jobs *jobs,const RyzFutexKey *key,uint32_t count,uint32_t mask)
{
    unsigned int i;uint32_t woke=0;
    for(i=0;i<RYZ_JOB_TASKS && woke<count;i++){
        Task *t=&jobs->tasks[i];
        if(t->state!=FREE && t->state!=ZOMBIE && t->futex_waiting && futex_equal(&t->futex_key,key) && (t->futex_mask&mask)){
            futex_clear(t);t->futex_woken=1;t->futex_deadline=0;woke++;
        }
    }
    return (int)woke;
}
static int futex_wake(Jobs *jobs,Task *caller,uint64_t address,uint32_t count,uint32_t mask)
{
    RyzFutexKey key;if(ryz_memory_futex_key(caller->cpu.m,address,0,&key))return 0;
    return futex_wake_key(jobs,&key,count,mask);
}
