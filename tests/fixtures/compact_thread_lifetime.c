/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static unsigned char stack[16384] __attribute__((aligned(16)));
static volatile int tid,word;
static unsigned char random_bytes[65536];
static char *challenge;static int kind;
static struct Head {U next;long offset;U pending;} head;
static struct Entry {U next;unsigned int lock;} entry;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
 __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static void print(const char *s){U n=0;while(s[n])n++;C(1,1,s,n);}
__attribute__((naked)) static long spawn(void *fn,void *top,U flags,volatile int *childtid)
{
 (void)fn;(void)top;(void)flags;(void)childtid;
 __asm__ volatile("mov %rdi,%r9; mov %rdx,%rdi; mov %rcx,%rdx; mov %rcx,%r10; xor %r8d,%r8d; and $-16,%rsi; mov $56,%eax; syscall; test %eax,%eax; jnz 1f; xor %ebp,%ebp; call *%r9; mov %eax,%edi; mov $60,%eax; syscall; ud2; 1: ret");
}
static long worker(void)
{
 if(kind==1){print("FLEX_RAW_THREADS_OK leader-exit\n");print(challenge);print("\n");return 0;}
 if(kind==2){C(231,17,0,0);return 90;}
 head.next=(U)&entry;head.offset=8;head.pending=0;entry.next=(U)&head;
 entry.lock=(unsigned int)C(186,0,0,0)|0x80000000U;
 if(C(273,&head,24,0))return 91;
 return 0;
}
long app_main(long argc,char **argv,char **env)
{
 U timeout[2]={0,1000000},pending=0,length=0;long n,pid;int status;(void)env;CHECK(argc==3);challenge=argv[2];
 if(equal(argv[1],"stopped-timer")){
  U mask=8192,timer[4]={0,1,0,1};CHECK(!call(14,0,(long)&mask,0,8,0,0) && !C(38,0,timer,0));C(62,C(39,0,0,0),19,0);return 94;
 }
 if(equal(argv[1],"clock-ceiling")){
  U target[2]={18446744073709UL,551615000},now[2]={0};CHECK(!C(230,1,1,target) && !C(228,1,now,0));CHECK(now[0]==target[0] && now[1]==target[1]);
  CHECK(!C(228,1,now,0) && now[0]==target[0] && now[1]==target[1]);print("FLEX_RAW_THREADS_OK clock-ceiling\n");print(challenge);print("\n");return 0;
 }
 if(equal(argv[1],"entropy-quota")){
  U i;for(i=0;i<16;i++)CHECK(C(318,random_bytes,sizeof random_bytes,0)==sizeof random_bytes);
  CHECK(C(318,random_bytes,1,0)==-28);print("FLEX_RAW_THREADS_OK entropy-quota\n");print(challenge);print("\n");return 0;
 }
 if(equal(argv[1],"leader-exit")){kind=1;CHECK(spawn(worker,stack+sizeof stack,0x310f00,&tid)>0);return 0;}
 if(equal(argv[1],"exit-group")){
  pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){kind=2;if(spawn(worker,stack+sizeof stack,0x310f00,&tid)<0)return 92;for(;;)C(24,0,0,0);}
  CHECK(C(61,pid,&status,0)==pid && status==(17<<8));
 }else if(equal(argv[1],"robust")){
  CHECK(spawn(worker,stack+sizeof stack,0x310f00,&tid)>0);
  while((n=tid)!=0){long result=call(202,(long)&tid,0,n,0,0,0);CHECK(result==0 || result==-11);}
  CHECK(entry.lock==0xc0000000U);
 }else if(equal(argv[1],"futex")){
  unsigned int same=7,partial=0x0302;
  __asm__ volatile("xaddl %0,%0":"+a"(same)::"cc");CHECK(same==14);
  __asm__ volatile("xaddb %%ah,%%al":"+a"(partial)::"cc");CHECK(partial==0x0205);
  CHECK(call(202,(long)&word,128,1,0,0,0)==-11);
  CHECK(call(202,(long)&word,128,0,(long)timeout,0,0)==-110);
  CHECK(call(202,(long)&word,129,1,0,0,0)==0);
  CHECK(call(202,(long)&word,129,-1,0,0,0)==0);
  CHECK(call(202,(long)&word+1,128,0,0,0,0)==-22);
  CHECK(call(202,(long)&word,137,0,(long)timeout,0,0)==-22);
  CHECK(call(202,(long)&word,132,1,1,(long)&tid,1)==-11);
  CHECK(C(273,&head,23,0)==-22 && C(273,&head,24,0)==0);
  CHECK(C(274,0,&pending,&length)==0 && pending==(U)&head && length==24);
  head.next=(U)&head;CHECK(C(273,0,24,0)==0);
 }else return 93;
 print("FLEX_RAW_THREADS_OK ");print(argv[1]);print("\n");print(challenge);print("\n");return 0;
}
