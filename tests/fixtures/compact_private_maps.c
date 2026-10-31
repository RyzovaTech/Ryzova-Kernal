/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;__asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int eq(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U len(const char *s){U n=0;while(s[n])n++;return n;}
static void print(const char *s){C(1,1,s,len(s));}
static long make(const char *path,const char *text){long fd=C(2,path,0102,0600);if(fd>=0 && C(1,fd,text,len(text))!=(long)len(text))return -100;return fd;}
static int content(const char *path,const char *text){char b[256];long fd=C(2,path,0,0),n;if(fd<0)return 0;n=C(0,fd,b,255);C(3,fd,0,0);if(n<0)return 0;b[n]=0;return eq(b,text);}
static volatile unsigned char *map(long fd,U size,U offset,long prot,long flags)
{return (volatile unsigned char *)call(9,0,size,prot,flags,fd,offset);}
static long file(U size)
{long fd=C(2,"file",0102,0600);if(fd>=0 && C(77,fd,size,0))return -100;return fd;}
long app_main(long argc,char **argv,char **env)
{
 long fd,ro,pid,status,n,i;volatile unsigned char *a,*b,*shared;char bytes[16];U st[18];(void)env;CHECK(argc==4);
 if(eq(argv[2],"exec-child")){
  CHECK(!C(80,argv[1],0,0));fd=C(2,"file",0,0);CHECK(fd>=0 && C(0,fd,bytes,1)==1 && bytes[0]=='A');
  print("FLEX_PRIVATE_OK exec\n");print(argv[3]);print("\n");return 0;
 }
 if(!eq(argv[2],"reload"))CHECK(!C(83,argv[1],0700,0));CHECK(!C(80,argv[1],0,0));
 if(eq(argv[2],"basic") || eq(argv[2],"create")){
  fd=file(4096);CHECK(fd>=0 && C(1,fd,"AB",2)==2 && !C(8,fd,0,0));
  a=map(fd,4096,0,3,2);b=map(fd,4096,0,3,2);CHECK((long)a>0 && (long)b>0 && a[0]=='A');
  a[0]='X';CHECK(a[0]=='X' && a[1]=='B' && b[0]=='A');
  CHECK(C(1,fd,"CD",2)==2 && a[0]=='X' && a[1]=='B');
  CHECK(!C(26,a,4096,4) && !C(8,fd,0,0) && C(0,fd,bytes,2)==2 && bytes[0]=='C' && bytes[1]=='D');
  CHECK(!C(11,a,4096,0) && !C(11,b,4096,0) && !C(3,fd,0,0));
 }else if(eq(argv[2],"reload")){
  fd=C(2,"file",0,0);CHECK(fd>=0 && C(0,fd,bytes,2)==2 && bytes[0]=='C' && bytes[1]=='D');
 }else if(eq(argv[2],"readonly")){
  fd=file(4096);CHECK(fd>=0 && C(1,fd,"A",1)==1);ro=C(2,"file",0,0);CHECK(ro>=0);
  a=map(ro,4096,0,3,2);CHECK((long)a>0);a[0]='X';CHECK(a[0]=='X');
  b=map(ro,4096,0,1,2);CHECK((long)b>0 && !C(10,b,4096,3));b[0]='Y';CHECK(a[0]=='X' && b[0]=='Y');
  CHECK(!C(8,fd,0,0) && C(0,fd,bytes,1)==1 && bytes[0]=='A');
 }else if(eq(argv[2],"fork")){
  int request[2],ack[2];fd=file(4096);CHECK(fd>=0 && C(1,fd,"A",1)==1);a=map(fd,4096,0,3,2);CHECK((long)a>0);
  a[0]='P';CHECK(!C(22,request,0,0) && !C(22,ack,0,0));pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){CHECK(C(0,request[0],bytes,1)==1 && a[0]=='P');a[0]='C';CHECK(C(1,ack[1],"x",1)==1);return 0;}
  a[0]='Q';CHECK(C(1,request[1],"x",1)==1 && C(0,ack[0],bytes,1)==1 && a[0]=='Q');
  CHECK(C(61,pid,&status,0)==pid && status==0 && !C(8,fd,0,0) && C(0,fd,bytes,1)==1 && bytes[0]=='A');
 }else if(eq(argv[2],"clean-fork")){
  fd=file(4096);CHECK(fd>=0 && C(1,fd,"A",1)==1);a=map(fd,4096,0,3,2);CHECK((long)a>0);pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){CHECK(a[0]=='A');a[0]='C';return 0;}
  CHECK(C(61,pid,&status,0)==pid && status==0 && a[0]=='A');a[0]='P';CHECK(!C(8,fd,0,0) && C(0,fd,bytes,1)==1 && bytes[0]=='A');
 }else if(eq(argv[2],"page-granularity")){
  fd=file(8192);CHECK(fd>=0);a=map(fd,8192,0,3,2);CHECK((long)a>0);a[0]='P';
  CHECK(C(1,fd,"F",1)==1 && C(8,fd,4096,0)==4096 && C(1,fd,"N",1)==1);
  a[4096]='Q';CHECK(a[0]=='P' && a[1]==0 && a[4096]=='Q');
  CHECK(C(8,fd,4096,0)==4096 && C(0,fd,bytes,1)==1 && bytes[0]=='N');
 }else if(eq(argv[2],"offset")){
  fd=file(8192);CHECK(fd>=0 && C(8,fd,4096,0)==4096 && C(1,fd,"O",1)==1);a=map(fd,4096,4096,3,2);CHECK((long)a>0 && a[0]=='O');a[0]='X';
  CHECK(C(8,fd,4096,0)==4096 && C(0,fd,bytes,1)==1 && bytes[0]=='O');
 }else if(eq(argv[2],"mixed")){
  fd=file(4096);CHECK(fd>=0);shared=map(fd,4096,0,3,1);a=map(fd,4096,0,3,2);CHECK((long)a>0 && (long)shared>0);
  a[0]='P';shared[0]='S';CHECK(a[0]=='P' && shared[0]=='S' && !C(8,fd,0,0) && C(0,fd,bytes,1)==1 && bytes[0]=='S');
 }else if(eq(argv[2],"io")){
  int pipe[2];fd=file(4096);CHECK(fd>=0 && C(1,fd,"A",1)==1);a=map(fd,4096,0,3,2);CHECK((long)a>0);
  CHECK(!C(22,pipe,0,0) && C(1,pipe[1],"X",1)==1 && C(0,pipe[0],a,1)==1 && a[0]=='X');
  CHECK(!C(8,fd,0,0) && C(0,fd,bytes,1)==1 && bytes[0]=='A');
 }else if(eq(argv[2],"unlink") || eq(argv[2],"release")){
  for(i=0;i<(eq(argv[2],"release")?40:1);i++){
   fd=file(4096);CHECK(fd>=0);a=map(fd,4096,0,3,2);CHECK((long)a>0 && !C(87,"file",0,0) && !C(3,fd,0,0));a[0]='X';
   n=file(4096);CHECK(n>=0);b=map(n,4096,0,3,2);CHECK((long)b>0 && a[0]=='X' && b[0]==0 && !C(11,b,4096,0) && !C(87,"file",0,0) && !C(3,n,0,0) && !C(11,a,4096,0));
  }
 }else if(eq(argv[2],"bus")){
  fd=file(4096);CHECK(fd>=0);a=map(fd,8192,0,3,2);CHECK((long)a>0);a[0]='P';CHECK(!C(77,fd,0,0));pid=C(57,0,0,0);CHECK(pid>=0);
  if(!pid){n=a[0];return n+91;}CHECK(C(61,pid,&status,0)==pid && (status&127)==7);
 }else if(eq(argv[2],"tail")){
  fd=file(3);CHECK(fd>=0);a=map(fd,4096,0,3,2);CHECK((long)a>0 && a[4095]==0);a[100]='P';
  CHECK(!C(5,fd,st,0) && st[6]==3 && !C(77,fd,1,0) && a[100]=='P');
  CHECK(!C(77,fd,4096,0));b=map(fd,4096,0,1,2);CHECK((long)b>0 && b[100]==0 && a[100]=='P');
 }else if(eq(argv[2],"fixed")){
  fd=file(4096);CHECK(fd>=0);a=map(fd,4096,0,3,2);CHECK((long)a>0);a[0]='X';
  CHECK(call(9,(long)a,4096,3,2|16,fd,0)==(long)a && a[0]==0);a[0]='Y';CHECK(!C(11,a,4096,0));
 }else if(eq(argv[2],"quota")){
  fd=file(65536);CHECK(fd>=0);for(i=0;i<4;i++){a=map(fd,65536,0,3,2);CHECK((long)a>0);}CHECK((long)map(fd,4096,0,3,2)==-12);
  CHECK(!C(11,a,65536,0) && (long)map(fd,65536,0,3,2)>0);
 }else if(eq(argv[2],"futex")){
  fd=file(4096);CHECK(fd>=0);a=map(fd,4096,0,3,2);CHECK((long)a>0 && call(202,(long)a,1,1,0,0,0)==0);
 }else if(eq(argv[2],"exec")){
  char *av[5]={argv[0],argv[1],"exec-child",argv[3],0},*ev[1]={0};fd=file(4096);CHECK(fd>=0 && C(1,fd,"A",1)==1);a=map(fd,4096,0,3,2);CHECK((long)a>0);a[0]='X';C(59,argv[0],av,ev);return 91;
 }else return 99;
 (void)st;print("FLEX_PRIVATE_OK ");print(argv[2]);print("\n");print(argv[3]);print("\n");return 0;
}
