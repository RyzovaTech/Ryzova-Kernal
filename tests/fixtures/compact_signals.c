/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static volatile long hits,inner,problem;static long ack=-1;
static unsigned char alternate[8192];
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
    register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
    __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
__attribute__((naked)) static void restorer(void){__asm__ volatile("mov $15,%eax; syscall; ud2");}
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static void handler(long sig,void *info,void *context)
{
    unsigned char *b=info;U mask=0;char byte='a';
    (void)context;hits++;
    if(sig!=10 && sig!=12 && sig!=32 && sig!=17 && sig!=14)problem=1;
    if(C(14,0,0,&mask) != -22)problem=2;
    if(call(14,0,0,(long)&mask,8,0,0) || !(mask & ((U)1<<(sig-1))))problem=3;
    if(b && *(int *)b!=sig)problem=4;
    if(ack>=0 && C(1,ack,&byte,1)!=1)problem=5;
}
static long action(long sig,void *fn,U flags,U mask)
{
    U data[4]={(U)fn,flags|0x04000000,(U)restorer,mask};
    return call(13,sig,(long)data,0,8,0,0);
}
static void nested(long sig,void *info,void *context)
{
    U mask=0;(void)info;(void)context;
    if(sig==12){inner++;return;}
    hits++;
    if(call(14,0,0,(long)&mask,8,0,0) || !(mask&512))problem=6;
    if(C(62,C(39,0,0,0),12,0) || inner!=1)problem=7;
}
static void on_alternate(long sig,void *info,void *context)
{
    char local;U old[3]={0};(void)sig;(void)info;(void)context;
    if((U)&local<(U)alternate || (U)&local>=(U)alternate+sizeof alternate)problem=8;
    if(C(131,0,old,0) || old[1]!=1)problem=9;
    hits++;
}
static void changed_context(long sig,void *info,void *context)
{
    (void)sig;(void)info;*(U *)((unsigned char *)context+40+104)=1234;hits++;
}
static void bad_context(long sig,void *info,void *context)
{
    (void)sig;(void)info;*(U *)((unsigned char *)context+40+128)=1;
}
static void vector_handler(long sig,void *info,void *context)
{
    (void)sig;(void)info;(void)context;hits++;
    __asm__ volatile("pxor %%xmm0,%%xmm0; clc":::"cc");
}
static void reentrant(long sig,void *info,void *context)
{
    U mask=0;(void)sig;(void)info;(void)context;hits++;
    if(call(14,0,0,(long)&mask,8,0,0) || (mask&512))problem=10;
    if(hits==1){C(62,C(39,0,0,0),10,0);if(hits!=2)problem=11;}
}
static long reap(long pid,int *status,long options)
{
    long n;do{n=C(61,pid,status,options);}while(n==-4);return n;
}
long app_main(long argc,char **argv,char **env)
{
    long pid,parent,n,i;U mask,old,pending,stack[3];int status,p[2],a[2];char byte;
    (void)env;CHECK(argc==3);parent=C(39,0,0,0);
    if(equal(argv[1],"sleep")){
        U before[2],after[2],request[2]={0,1000000},zero[2]={0,0};
        CHECK(C(228,1,before,0)==0 && C(35,request,0,0)==0 && C(228,1,after,0)==0);
        CHECK(after[0]>before[0] || (after[0]==before[0] && after[1]>=before[1]+1000000));
        CHECK(C(230,1,1,zero)==0);request[1]=1000000000;CHECK(C(35,request,0,0)==-22);
    }else if(equal(argv[1],"timer")){
        U setting[4]={0,2000,0,1000},oldtimer[4]={0},request[2]={0,100000000},remain[2]={0};
        CHECK(action(14,(void *)handler,4|0x10000000,0)==0 && C(38,0,setting,oldtimer)==0);
        CHECK(C(35,request,remain,0)==-4 && hits>=1 && remain[1]>0 && !problem);
        setting[0]=setting[1]=setting[2]=setting[3]=0;CHECK(C(38,0,setting,oldtimer)==0 && oldtimer[1]==2000);
        CHECK(C(36,0,oldtimer,0)==0 && !oldtimer[2] && !oldtimer[3]);
    }else if(equal(argv[1],"alarm")){
        CHECK(action(14,(void *)handler,4,0)==0 && C(37,1,0,0)==0);
        CHECK(C(34,0,0,0)==-4 && hits==1 && !problem && C(37,0,0,0)==0);
    }else if(equal(argv[1],"sigwait")){
        U info[16],timeout[2]={0,1000000};mask=512;
        CHECK(call(14,0,(long)&mask,0,8,0,0)==0 && C(62,parent,10,0)==0);
        CHECK(call(128,(long)&mask,(long)info,(long)timeout,8,0,0)==10 && *(unsigned int *)info==10);
        CHECK(call(128,(long)&mask,(long)info,(long)timeout,8,0,0)==-11);
    }else if(equal(argv[1],"vector")){
        U seed[2]={0x123456789abcdef0UL,0x1020304050607080UL},out[2]={0};unsigned char carry=0;
        CHECK(action(10,(void *)vector_handler,4,0)==0);
        __asm__ volatile("movups (%3),%%xmm0; mov $62,%%eax; mov $10,%%esi; stc; syscall; setc %0; movups %%xmm0,(%4)":"=m"(carry):"D"(parent),"m"(seed),"r"(seed),"r"(out):"rax","rsi","rcx","r11","cc","memory");
        CHECK(hits==1 && carry && out[0]==seed[0] && out[1]==seed[1]);
    }else if(equal(argv[1],"nodefer")){
        CHECK(action(10,(void *)reentrant,4|0x40000000,0)==0);
        CHECK(C(62,parent,10,0)==0 && hits==2 && !problem);
    }else if(equal(argv[1],"reset")){
        U oldaction[4]={0};
        CHECK(action(10,(void *)handler,4|0x80000000,0)==0 && C(62,parent,10,0)==0 && hits==1);
        CHECK(call(13,10,0,(long)oldaction,8,0,0)==0 && !oldaction[0]);
    }else if(equal(argv[1],"tkill")){
        CHECK(action(10,(void *)handler,4,0)==0 && C(200,parent,10,0)==0 && hits==1);
        CHECK(C(234,parent,parent,10)==0 && hits==2 && !problem);
        CHECK(C(234,parent,parent+999,10)==-3 && C(62,2147483647,0,0)==-3);
    }else if(equal(argv[1],"rt-quota")){
        mask=(U)1<<31;CHECK(action(32,(void *)handler,4,0)==0 && call(14,0,(long)&mask,0,8,0,0)==0);
        for(i=0;i<33;i++)CHECK(C(62,parent,32,0)==0);
        CHECK(C(62,parent,32,0)==-11);
        CHECK(call(14,1,(long)&mask,0,8,0,0)==0 && hits==33 && !problem);
    }else if(equal(argv[1],"handler")){
        CHECK(action(10,(void *)handler,4,0)==0 && C(62,parent,10,0)==0);
        CHECK(hits==1 && !problem);
        CHECK(action(10,(void *)changed_context,4,0)==0 && C(62,parent,10,0)==1234 && hits==2);
    }else if(equal(argv[1],"mask")){
        mask=512;CHECK(action(10,(void *)handler,4,0)==0 && call(14,0,(long)&mask,0,8,0,0)==0);
        CHECK(C(62,parent,10,0)==0 && C(62,parent,10,0)==0 && hits==0);
        CHECK(C(127,&pending,8,0)==0 && pending==512);
        mask=0;CHECK(C(130,&mask,8,0)==-4 && hits==1 && !problem);
        CHECK(call(14,0,0,(long)&old,8,0,0)==0 && old==512);
        mask=((U)1<<8)|((U)1<<18);CHECK(call(14,2,(long)&mask,(long)&old,8,0,0)==0);
        CHECK(call(14,0,0,(long)&old,8,0,0)==0 && !old);
    }else if(equal(argv[1],"nested")){
        CHECK(action(10,(void *)nested,4,0)==0 && action(12,(void *)nested,4,0)==0);
        CHECK(C(62,parent,10,0)==0 && hits==1 && inner==1 && !problem);
        CHECK(call(14,0,0,(long)&old,8,0,0)==0 && !old);
    }else if(equal(argv[1],"restart") || equal(argv[1],"eintr")){
        CHECK(C(22,p,0,0)==0 && C(22,a,0,0)==0);ack=a[1];
        CHECK(action(10,(void *)handler,4|(equal(argv[1],"restart")?0x10000000:0),0)==0);
        pid=C(57,0,0,0);CHECK(pid>=0);
        if(!pid){
            CHECK(C(62,parent,10,0)==0 && C(0,a[0],&byte,1)==1);
            CHECK(C(1,p[1],"Z",1)==1);return 7;
        }
        n=C(0,p[0],&byte,1);
        if(equal(argv[1],"eintr")){CHECK(n==-4);n=C(0,p[0],&byte,1);}
        CHECK(n==1 && byte=='Z' && hits==1 && !problem && reap(pid,&status,0)==pid && status==(7<<8));
    }else if(equal(argv[1],"alternate")){
        stack[0]=(U)alternate;stack[1]=0;stack[2]=sizeof alternate;
        CHECK(C(131,stack,0,0)==0 && action(10,(void *)on_alternate,4|0x08000000,0)==0);
        CHECK(C(62,parent,10,0)==0 && hits==1 && !problem);
        CHECK(C(131,0,stack,0)==0 && !stack[1]);stack[1]=2;CHECK(C(131,stack,0,0)==0);
    }else if(equal(argv[1],"stop")){
        pid=C(57,0,0,0);CHECK(pid>=0);
        if(!pid){CHECK(C(62,C(39,0,0,0),19,0)==0);for(;;)C(34,0,0,0);}
        CHECK(reap(pid,&status,2)==pid && status==((19<<8)|127));
        CHECK(C(62,pid,18,0)==0 && reap(pid,&status,8)==pid && status==65535);
        CHECK(C(62,pid,15,0)==0 && reap(pid,&status,0)==pid && (status&127)==15);
    }else if(equal(argv[1],"fatal") || equal(argv[1],"bad-frame")){
        pid=C(57,0,0,0);CHECK(pid>=0);
        if(!pid){if(equal(argv[1],"bad-frame"))CHECK(action(10,(void *)bad_context,4,0)==0);C(62,C(39,0,0,0),10,0);return 99;}
        CHECK(reap(pid,&status,0)==pid && (status&127)==(equal(argv[1],"fatal")?10:11));
    }else if(equal(argv[1],"realtime")){
        mask=(U)1<<31;CHECK(action(32,(void *)handler,4,0)==0 && call(14,0,(long)&mask,0,8,0,0)==0);
        for(i=0;i<3;i++)CHECK(C(62,parent,32,0)==0);
        CHECK(C(127,&pending,8,0)==0 && pending==mask);
        CHECK(call(14,1,(long)&mask,0,8,0,0)==0 && hits==3 && !problem);
    }else if(equal(argv[1],"no-zombie")){
        CHECK(action(17,(void *)1,0,0)==0);pid=C(57,0,0,0);CHECK(pid>=0);if(!pid)return 7;
        CHECK(reap(pid,&status,0)==-10);
    }else return 90;
    CHECK(C(1,1,"FLEX_SIGNALS_OK\n",16)==16);CHECK(C(1,1,argv[2],len(argv[2]))==(long)len(argv[2]));CHECK(C(1,1,"\n",1)==1);return 0;
}
