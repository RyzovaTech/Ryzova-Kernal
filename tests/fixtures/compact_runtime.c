/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;__asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int eq(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static void print(const char *s){C(1,1,s,len(s));}
static volatile int *map(long fd,long flags,U size){return (volatile int *)call(9,0,size,3,flags,fd,0);}
static long fut(volatile int *at,int op,long value,U arg,volatile int *to,U mask){return call(202,(long)at,op,value,arg,(long)to,mask);}
static int waitok(long pid){long status=0;return C(61,pid,&status,0)==pid && status==0;}
static unsigned char thread_stack[16384] __attribute__((aligned(16)));
static volatile int child_tid,wait_result;
static volatile int *wait_address;
__attribute__((naked)) static long spawn(void *fn,void *top,U flags,volatile int *childtid)
{
 (void)fn;(void)top;(void)flags;(void)childtid;
 __asm__ volatile("mov %rdi,%r9; mov %rdx,%rdi; mov %rcx,%rdx; mov %rcx,%r10; xor %r8d,%r8d; and $-16,%rsi; mov $56,%eax; syscall; test %eax,%eax; jnz 1f; xor %ebp,%ebp; call *%r9; mov %eax,%edi; mov $60,%eax; syscall; ud2; 1: ret");
}
static long waiter(void)
{U timeout[2]={0,100000000};wait_result=(int)fut(wait_address,0,1,(U)timeout,0,0);return 0;}
long app_main(long argc,char **argv,char **env)
{
 volatile int *a,*b,*priv;long pid,fd,n,i;U limit[2],old[2],pidself,group,sid,deadline[2]={0,1000000};(void)env;
 CHECK(argc==4);
 if(eq(argv[2],"exec-child")){CHECK(!C(97,7,old,0) && old[0]==5);print("FLEX_PROC_RESOURCE_OK exec\n");print(argv[3]);print("\n");return 0;}
 if(eq(argv[2],"unmap-wait") || eq(argv[2],"key-pin-quota")){
  a=map(-1,33,4096);CHECK((long)a>0);a[0]=1;a[1]=2;wait_address=a;wait_result=1;
  CHECK(spawn(waiter,thread_stack+sizeof thread_stack,0x1310f00,&child_tid)>0);
  for(i=0;i<2000;i++){n=fut(a,4,0,1,a+1,1);CHECK(n>=0);if(n)break;C(35,deadline,0,0);}CHECK(n==1);
  CHECK(!C(11,a,4096,0));b=map(-1,33,63*4096);CHECK((long)b>0);
  if(eq(argv[2],"key-pin-quota"))CHECK((long)map(-1,33,4096)==-12);
  while((n=child_tid)!=0){long v=fut(&child_tid,0,n,0,0,0);CHECK(v==0 || v==-11);}
  CHECK(wait_result==-110 && !C(11,b,63*4096,0));a=map(-1,33,64*4096);CHECK((long)a>0);
 }else if(eq(argv[2],"basic") || eq(argv[2],"fork") || eq(argv[2],"release") || eq(argv[2],"quota") || eq(argv[2],"fixed")){
  a=map(-1,33,8192);CHECK((long)a>0);a[0]=11;a[1024]=22;
  priv=map(-1,34,4096);CHECK((long)priv>0);priv[0]=33;
  if(eq(argv[2],"basic") || eq(argv[2],"fork")){
   pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){CHECK(a[0]==11 && a[1024]==22 && priv[0]==33);a[0]=44;a[1024]=55;priv[0]=66;return 0;}
   CHECK(waitok(pid) && a[0]==44 && a[1024]==55 && priv[0]==33);
   CHECK(!C(10,a,8192,1) && a[0]==44 && !C(10,a,8192,3));
  }else if(eq(argv[2],"fixed")){
   CHECK(call(9,(long)a,4096,3,49,-1,0)==(long)a && !a[0] && a[1024]==22);
   CHECK(call(9,(long)a,4096,3,50,-1,0)==(long)a && !a[0] && a[1024]==22);
  }else if(eq(argv[2],"release")){
   CHECK(!C(11,a,8192,0));for(i=0;i<80;i++){a=map(-1,33,4096);CHECK((long)a>0 && !a[0]);a[0]=99;CHECK(!C(11,a,4096,0));}
  }else{
   CHECK(!C(11,a,8192,0));a=map(-1,33,64*4096);CHECK((long)a>0 && (long)map(-1,33,4096)==-12);CHECK(!C(11,a,64*4096,0));CHECK((long)map(-1,33,4096)>0);
  }
 }else if(eq(argv[2],"anon-futex") || eq(argv[2],"file-futex") || eq(argv[2],"private-futex") || eq(argv[2],"bitset") || eq(argv[2],"requeue") || eq(argv[2],"timeout")){
  int file=eq(argv[2],"file-futex"),private_key=eq(argv[2],"private-futex"),op=private_key?128:0;int pipes[2];unsigned char ch;
  fd=-1;if(file){fd=C(2,argv[1],0102,0600);CHECK(fd>=0 && !C(77,fd,4096,0));}
  a=map(fd,file?1:33,4096);CHECK((long)a>0);a[0]=1;a[1]=2;
  b=file?map(fd,1,4096):a;CHECK((long)b>0);
  if(eq(argv[2],"timeout")){CHECK(fut(a,0,1,(U)deadline,0,0)==-110 && fut(a,1,1,0,0,0)==0);}
  else{
   CHECK(!C(22,pipes,0,0));pid=C(57,0,0,0);CHECK(pid>=0);
   if(!pid){
    CHECK(C(1,pipes[1],"x",1)==1);
    if(private_key){CHECK(fut(a,128,1,(U)deadline,0,0)==-110);return 0;}
    if(eq(argv[2],"bitset")){CHECK(fut(a,9,1,0,0,2)==0);return 0;}
    CHECK(fut(a,op,1,0,0,0)==0);return 0;
   }
   CHECK(C(0,pipes[0],&ch,1)==1);
   if(private_key){CHECK(fut(b,129,1,0,0,0)==0);}
   else if(eq(argv[2],"bitset")){
    CHECK(fut(b,10,1,0,0,1)==0);for(i=0;i<2000;i++){n=fut(b,10,1,0,0,2);CHECK(n>=0);if(n)break;C(35,deadline,0,0);}CHECK(n==1);
   }else if(eq(argv[2],"requeue")){
    for(i=0;i<2000;i++){n=fut(b,4,0,1,b+1,1);CHECK(n>=0);if(n)break;C(35,deadline,0,0);}CHECK(n==1 && fut(b,1,1,0,0,0)==0);CHECK(fut(b+1,1,1,0,0,0)==1);
   }else{
    for(i=0;i<2000;i++){n=fut(b,1,1,0,0,0);CHECK(n>=0);if(n)break;C(35,deadline,0,0);}CHECK(n==1);
   }
   CHECK(waitok(pid));
  }
 }else if(eq(argv[2],"sessions")){
  pidself=C(39,0,0,0);group=C(111,0,0,0);sid=C(124,0,0,0);CHECK((long)sid>0 && C(121,0,0,0)==(long)group && C(121,999999,0,0)==-3);
  pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){U own=C(39,0,0,0);CHECK(C(121,0,0,0)==(long)group && C(124,0,0,0)==(long)sid);CHECK(C(112,0,0,0)==(long)own && C(124,0,0,0)==(long)own && C(111,0,0,0)==(long)own);CHECK(C(112,0,0,0)==-1 && C(109,0,0,0)==-1);return 0;}
  CHECK(waitok(pid) && C(124,0,0,0)==(long)sid && C(121,pidself,0,0)==(long)group);
 }else if(eq(argv[2],"groups")){
  int pipes[2];unsigned char ch;CHECK(!C(22,pipes,0,0));pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){CHECK(C(0,pipes[0],&ch,1)==1 && C(111,0,0,0)==C(39,0,0,0));return 0;}
  CHECK(!C(109,pid,pid,0) && C(121,pid,0,0)==pid && C(1,pipes[1],"x",1)==1 && waitok(pid));
 }else if(eq(argv[2],"nofile") || eq(argv[2],"exec")){
  CHECK(!C(97,7,old,0) && old[0]>=8);limit[0]=5;limit[1]=old[1];CHECK(!C(160,7,limit,0));
  CHECK(!C(97,7,old,0) && old[0]==5);fd=C(2,"/dev/null",0,0);CHECK(fd==3);n=C(32,fd,0,0);CHECK(n==4 && C(32,fd,0,0)==-24);
  CHECK(C(33,fd,5,0)==-9 && !C(3,n,0,0));limit[0]=3;CHECK(!C(160,7,limit,0) && C(2,"/dev/null",0,0)==-24 && C(0,fd,&n,1)==0 && !C(3,fd,0,0));
  limit[0]=5;CHECK(!C(160,7,limit,0));
  if(eq(argv[2],"exec")){char *av[5]={argv[0],argv[1],"exec-child",argv[3],0},*ev[1]={0};C(59,argv[0],av,ev);return 91;}
  pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){CHECK(!C(97,7,old,0) && old[0]==5);return 0;}CHECK(waitok(pid));
 }else if(eq(argv[2],"hard-limit")){
  CHECK(!C(97,7,old,0));limit[0]=4;limit[1]=4;CHECK(!C(160,7,limit,0));limit[0]=5;limit[1]=5;CHECK(C(160,7,limit,0)==-1);limit[0]=5;limit[1]=4;CHECK(C(160,7,limit,0)==-22);CHECK(!C(97,7,old,0) && old[0]==4 && old[1]==4);
 }else if(eq(argv[2],"nproc")){
  CHECK(!C(97,6,old,0));limit[0]=1;limit[1]=old[1];CHECK(!C(160,6,limit,0) && C(57,0,0,0)==-11);
 }else if(eq(argv[2],"address-limit")){
  CHECK(!C(97,9,old,0));limit[0]=0;limit[1]=old[1];CHECK(!C(160,9,limit,0));CHECK((long)map(-1,34,4096)==-12);n=C(12,0,0,0);CHECK(C(12,n+4096,0,0)==n);
  CHECK(!C(160,9,old,0) && (long)map(-1,34,4096)>0);
 }else if(eq(argv[2],"arena-budget")){
  char *av[5]={argv[0],argv[1],"exec-child",argv[3],0},*ev[1]={0};
  a=map(-1,33,4096);CHECK((long)a>0);a[0]=123;
  CHECK(C(57,0,0,0)==-12 && C(59,argv[0],av,ev)==-12 && a[0]==123);
 }else if(eq(argv[2],"prlimit")){
  CHECK(!C(97,7,old,0));limit[0]=5;limit[1]=old[1];CHECK(!call(302,0,7,(long)limit,(long)old,0,0) && old[0]>=8);CHECK(!C(97,7,old,0) && old[0]==5);
  limit[0]=4;CHECK(call(302,0,7,(long)limit,1,0,0)==-14 && !C(97,7,old,0) && old[0]==4);
  CHECK(C(97,99,old,0)==-22 && C(97,7,1,0)==-14);
 }else return 99;
 print("FLEX_PROC_RESOURCE_OK ");print(argv[2]);print("\n");print(argv[3]);print("\n");return 0;
}
