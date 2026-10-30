/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static volatile long hits,problem;static int check_context;static unsigned char alternate[8192];static long repair_fd;static U expected_address;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;__asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
__attribute__((naked)) static void restorer(void){__asm__ volatile("mov $15,%eax; syscall; ud2");}
static int eq(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static void print(const char *s){C(1,1,s,len(s));}
static volatile unsigned char *mapping(long fd,U size,U off,long prot){return (volatile unsigned char *)call(9,0,size,prot,1,fd,off);}
static long make(U size){long fd=C(2,"file",0102,0600);if(fd>=0 && C(77,fd,size,0))return -100;return fd;}
static void on_bus(long sig,void *info,void *context)
{unsigned char *b=info;hits++;if(check_context==1 && *(U *)((unsigned char *)context+72)!=0x1234)problem=3;if(check_context==2 && !(*(U *)((unsigned char *)context+176)&1))problem=4;if(sig!=7 || *(int *)(b+8)!=2 || *(U *)(b+16)!=expected_address)problem=1;if(C(77,repair_fd,8192,0))problem=2;}
long app_main(long argc,char **argv,char **env)
{
 long fd,ro,pid,status,n,i,pair[2],q[2];volatile unsigned char *a,*b,*c;unsigned char bytes[32];U st[18];(void)env;CHECK(argc==4 || (argc==5 && eq(argv[2],"exec-cycle")));
 if(eq(argv[2],"exec-child")){CHECK(!C(80,argv[1],0,0));fd=C(2,"file",0,0);CHECK(fd>=0 && C(0,fd,bytes,1)==1 && bytes[0]=='E');print("FLEX_MAP_OK exec\n");print(argv[3]);print("\n");return 0;}
 if(!eq(argv[2],"reload") && !eq(argv[2],"fault-reload") && !(argc==5 && eq(argv[2],"exec-cycle")))CHECK(!C(83,argv[1],0700,0));CHECK(!C(80,argv[1],0,0));
 if(eq(argv[2],"basic") || eq(argv[2],"create")){
  fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0);b=mapping(fd,4096,0,3);CHECK((long)b>0);
  a[0]='A';CHECK(b[0]=='A');b[1]='B';CHECK(a[1]=='B');CHECK(C(0,fd,bytes,2)==2 && bytes[0]=='A' && bytes[1]=='B');
  CHECK(!C(8,fd,0,0) && C(1,fd,"CD",2)==2 && a[0]=='C' && b[1]=='D');
  CHECK(!C(86,"file","alias",0) && !C(3,fd,0,0));a[2]='E';CHECK(!C(26,a,4096,4));
  fd=C(2,"alias",0,0);CHECK(fd>=0 && C(0,fd,bytes,3)==3 && bytes[2]=='E' && !C(3,fd,0,0));
  CHECK(!C(11,a,4096,0) && !C(11,b,4096,0));
 }else if(eq(argv[2],"reload")){
  fd=C(2,"alias",2,0);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0 && a[0]=='C' && a[1]=='D' && a[2]=='E');
  CHECK(!C(4,"file",st,0) && st[2]==2);
 }else if(eq(argv[2],"fault")){
  fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0);a[0]='F';for(;;)__asm__ volatile("nop");
 }else if(eq(argv[2],"fault-reload")){
  fd=C(2,"file",0,0);CHECK(fd>=0);a=mapping(fd,4096,0,1);CHECK((long)a>0 && a[0]=='F');
 }else if(eq(argv[2],"fork")){
  int pipes[2],ack[2];fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0);a[0]='P';CHECK(!C(22,pipes,0,0) && !C(22,ack,0,0));
  pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){if(C(0,pipes[0],bytes,1)!=1 || a[0]!='Q')return 91;a[1]='R';if(C(1,ack[1],"x",1)!=1)return 92;return 0;}
  a[0]='Q';CHECK(C(1,pipes[1],"x",1)==1 && C(0,ack[0],bytes,1)==1 && a[1]=='R');CHECK(C(61,pid,&status,0)==pid && status==0);
 }else if(eq(argv[2],"unlink")){
  fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0 && !C(87,"file",0,0) && !C(3,fd,0,0));a[0]='K';
  for(i=0;i<40;i++){n=C(2,"temp",0102,0600);CHECK(n>=0 && C(1,n,"N",1)==1 && !C(87,"temp",0,0) && !C(3,n,0,0));}
  b=mapping((fd=make(4096)),4096,0,3);CHECK(fd>=0 && (long)b>0 && a[0]=='K' && b[0]==0 && !C(11,a,4096,0));
 }else if(eq(argv[2],"tail")){
  fd=make(3);CHECK(fd>=0);a=mapping(fd,4096,0,3);b=mapping(fd,4096,0,3);CHECK((long)a>0 && (long)b>0 && a[4095]==0);
  a[0]='A';a[100]='T';CHECK(b[100]=='T' && !C(5,fd,st,0) && st[6]==3 && !C(26,a,4096,4));
  CHECK(!C(77,fd,4096,0) && a[100]==0 && b[100]==0);a[100]='X';CHECK(!C(77,fd,3,0) && a[100]==0);
 }else if(eq(argv[2],"bus")){
  fd=make(4096);CHECK(fd>=0);a=mapping(fd,8192,0,3);CHECK((long)a>0);
  pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){a[4096]=1;return 91;}
  CHECK(C(61,pid,&status,0)==pid && (status&127)==7);
  CHECK(!C(77,fd,0,0));pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){n=a[0];return n+91;}
  CHECK(C(61,pid,&status,0)==pid && (status&127)==7 && !C(77,fd,8192,0) && a[4096]==0);
 }else if(eq(argv[2],"bus-handler")){
  U action[4]={(U)on_bus,0x04000004,(U)restorer,0};fd=make(4096);CHECK(fd>=0);repair_fd=fd;a=mapping(fd,8192,0,3);CHECK((long)a>0);expected_address=(U)a+4096;
  CHECK(!call(13,7,(long)action,0,8,0,0));a[4096]='H';CHECK(hits==1 && !problem && a[4096]=='H');
 }else if(eq(argv[2],"bus-context")){
  U action[4]={(U)on_bus,0x0c000004,(U)restorer,0},stack[3]={(U)alternate,0,sizeof alternate};register U value __asm__("r12")=0x1234;
  fd=make(4096);CHECK(fd>=0);repair_fd=fd;a=mapping(fd,8192,0,3);CHECK((long)a>0);expected_address=(U)a+4096;check_context=1;
  CHECK(!C(131,stack,0,0) && !call(13,7,(long)action,0,8,0,0));
  __asm__ volatile("mov %%rsp,%%r15; mov %1,%%rsp; pop %%r12; mov %%r15,%%rsp":"+r"(value):"r"(expected_address):"r15","memory");
  CHECK(hits==1 && !problem && value==0);
 }else if(eq(argv[2],"bus-flags")){
  U action[4]={(U)on_bus,0x0c000004,(U)restorer,0},stack[3]={(U)alternate,0,sizeof alternate},flags;
  fd=make(4096);CHECK(fd>=0);repair_fd=fd;a=mapping(fd,8192,0,3);CHECK((long)a>0);expected_address=(U)a+4096;check_context=2;
  CHECK(!C(131,stack,0,0) && !call(13,7,(long)action,0,8,0,0));
  __asm__ volatile("stc; mov %%rsp,%%r15; mov %1,%%rsp; popfq; mov %%r15,%%rsp; pushfq; pop %0":"=r"(flags):"r"(expected_address):"r15","memory","cc");
  CHECK(hits==1 && !problem && !(flags&1));
 }else if(eq(argv[2],"permissions")){
  fd=make(4096);CHECK(fd>=0);ro=C(2,"file",0,0);CHECK(ro>=0 && (long)mapping(ro,4096,0,3)==-13);
  a=mapping(ro,4096,0,1);CHECK((long)a>0 && C(10,a,4096,3)==-13 && !C(10,a,4096,0) && !C(10,a,4096,1));
  CHECK((long)mapping(fd,4096,0,7)==-1 && C(10,a,4096,5)==-1);
 }else if(eq(argv[2],"offset")){
  fd=make(8192);CHECK(fd>=0);a=mapping(fd,8192,0,3);b=mapping(fd,4096,4096,3);CHECK((long)a>0 && (long)b>0);
  a[4096]='O';CHECK(b[0]=='O');b[4095]='Z';CHECK(a[8191]=='Z');CHECK(!C(11,a+4096,4096,0) && b[0]=='O');
 }else if(eq(argv[2],"fixed")){
  fd=make(8192);CHECK(fd>=0);a=mapping(fd,8192,0,3);CHECK((long)a>0);a[0]='F';
  CHECK(call(9,(long)a,4096,3,1|16,fd,4096)==(long)a && a[0]==0);a[0]='N';
  b=mapping(fd,8192,0,3);CHECK((long)b>0 && b[0]=='F' && b[4096]=='N');
  CHECK(call(9,(long)a,4096,3,34|16,-1,0)==(long)a);a[0]='A';CHECK(b[4096]=='N');
 }else if(eq(argv[2],"io")){
  U v[4];int pipes[2];fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);b=mapping(fd,4096,0,3);CHECK((long)a>0 && (long)b>0);
  CHECK(!C(22,pipes,0,0) && C(1,pipes[1],"hello",5)==5 && C(0,pipes[0],a,5)==5 && b[0]=='h' && b[4]=='o');
  v[0]=(U)a+8;v[1]=1;v[2]=(U)a+16;v[3]=1;CHECK(C(1,pipes[1],"XY",2)==2 && C(19,pipes[0],v,2)==2 && b[8]=='X' && b[16]=='Y');
  CHECK(!C(5,fd,a+128,0) && *(volatile U *)(b+176)==4096);
 }else if(eq(argv[2],"syscall-fault")){
  int pipes[2];fd=make(0);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0 && !C(22,pipes,0,0) && C(1,pipes[1],"x",1)==1);
  CHECK(C(0,pipes[0],a,1)==-14 && !C(77,fd,4096,0) && C(0,pipes[0],a,1)==1 && a[0]=='x');
 }else if(eq(argv[2],"bus-blocked")){
  U mask=64,action[4]={1,0x04000000,(U)restorer,0};fd=make(0);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0);
  for(i=0;i<2;i++){pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){if(i==0)call(14,0,(long)&mask,0,8,0,0);else call(13,7,(long)action,0,8,0,0);a[0]=1;return 91;}CHECK(C(61,pid,&status,0)==pid && (status&127)==7);}
 }else if(eq(argv[2],"errors")){
  fd=make(8192);CHECK(fd>=0);a=mapping(fd,12288,0,3);CHECK((long)a>0 && !C(11,a+8192,4096,0));a[0]='S';
  CHECK((long)mapping(fd,4096,1,3)==-22 && (long)mapping(-1,4096,0,3)==-9);
  CHECK(C(26,a+1,4096,4)==-22 && C(26,a,4096,5)==-22 && !C(26,a,0,4));
  CHECK(C(10,a,12288,1)==-12 && !C(10,a,8192,3));a[0]='T';CHECK(a[0]=='T');
  CHECK(!C(11,a+4096,4096,0) && C(26,a,8192,4)==-12 && a[0]=='T');
 }else if(eq(argv[2],"output-alias")){
  U v[4];int pipes[2];fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);b=mapping(fd,4096,0,3);CHECK((long)a>0 && (long)b>0 && !C(22,pipes,0,0));
  v[0]=(U)a;v[1]=1;v[2]=(U)b+8;v[3]=1;CHECK(C(1,pipes[1],"XY",2)==2 && C(19,pipes[0],v,2)==-14 && a[0]==0 && b[8]==0);
 }else if(eq(argv[2],"futex-policy")){
  fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0);
  CHECK(call(202,(long)a,1,1,0,0,0)==-95 && call(202,(long)a,129,1,0,0,0)==0);
 }else if(eq(argv[2],"release")){
  for(i=0;i<40;i++){
   fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0 && !C(87,"file",0,0) && !C(3,fd,0,0));a[0]='R';
   if(i<8){pid=C(57,0,0,0);CHECK(pid>=0);if(!pid)return a[0]=='R'?0:91;CHECK(C(61,pid,&status,0)==pid && status==0);}
   CHECK(!C(11,a,4096,0));
  }
 }else if(eq(argv[2],"quota")){
  fd=make(65536);CHECK(fd>=0);for(i=0;i<4;i++){a=mapping(fd,65536,0,3);CHECK((long)a>0);pair[i%2]=(long)a;}
  CHECK((long)mapping(fd,4096,0,3)==-12 && !C(11,pair[1],65536,0));a=mapping(fd,65536,0,3);CHECK((long)a>0);
 }else if(eq(argv[2],"exec-cycle")){
  long round=argc==5?(argv[4][0]-'0')*10+argv[4][1]-'0':0;
  if(round<34){char number[3]={(char)('0'+(round+1)/10),(char)('0'+(round+1)%10),0};char *av[6]={argv[0],argv[1],"exec-cycle",argv[3],number,0},*ev[1]={0};
   fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0 && !C(87,"file",0,0) && !C(3,fd,0,0));a[0]='E';C(59,argv[0],av,ev);return 91;
  }
 }else if(eq(argv[2],"exec")){
  char *av[5]={argv[0],argv[1],"exec-child",argv[3],0},*ev[1]={0};fd=make(4096);CHECK(fd>=0);a=mapping(fd,4096,0,3);CHECK((long)a>0);a[0]='E';C(59,argv[0],av,ev);return 91;
 }else return 99;
 (void)c;(void)q;print("FLEX_MAP_OK ");print(argv[2]);print("\n");print(argv[3]);print("\n");return 0;
}
