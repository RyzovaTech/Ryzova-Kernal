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
long app_main(long argc,char **argv,char **env)
{
 long fd,dir,other,pid,status,n;char b[256];U st[18];char *av[4],*ep[1]={0};(void)env;CHECK(argc==3);
 if(eq(argv[1],"create")){
  CHECK(!C(83,"/home/share/project",0700,0));fd=make("/home/share/project/main.c",argv[2]);CHECK(fd>=0 && !C(3,fd,0,0));
  CHECK(!C(90,"/home/share/project/main.c",0640,0));
  CHECK(!C(82,"/home/share/project/main.c","/home/share/project/source.c",0));
  CHECK(content("/home/share/project/source.c",argv[2]));
  CHECK(!C(80,"/home/share/project",0,0) && C(79,b,256,0)==20 && eq(b,"/home/share/project"));
  fd=C(2,"source.c",0,0);CHECK(fd>=0 && !C(5,fd,st,0) && st[6]==len(argv[2]) && !C(3,fd,0,0));
  dir=C(2,".",0200000,0);CHECK(dir>=0 && C(217,dir,b,256)>0 && !C(81,dir,0,0));
  fd=call(257,dir,(long)"other",0102,0600,0,0);CHECK(fd>=0 && !C(3,fd,0,0));
  CHECK(!C(87,"other",0,0) && !C(3,dir,0,0));
 }else if(eq(argv[1],"reload")){
  CHECK(content("/home/share/project/source.c",argv[2]));
  fd=C(2,"/home/share/project/source.c",02002,0);CHECK(fd>=0 && C(1,fd,"!",1)==1 && !C(3,fd,0,0));
 }else if(eq(argv[1],"check")){
  fd=C(2,"/home/share/project/source.c",0,0);CHECK(fd>=0);n=C(0,fd,b,255);CHECK(n==(long)len(argv[2])+1 && b[n-1]=='!');b[n-1]=0;CHECK(eq(b,argv[2]));
 }else if(eq(argv[1],"readonly")){
  CHECK(content("/home/share/project/source.c",argv[2]));
  CHECK(C(2,"/home/share/new",0102,0600)==-13 && C(76,"/home/share/project/source.c",0,0)==-13);
 }else if(eq(argv[1],"views")){
  fd=C(2,"/home/share/project/source.c",2,0);CHECK(fd>=0);
  CHECK(!call(157,0x46534e53,1,0,0,0,0));CHECK(C(1,fd,"BAD",3)==-13 && C(8,fd,0,0)==0 && C(0,fd,b,1)==1);
  CHECK(call(157,0x46534e53,1,1,0,0,0)==-1);
  pid=C(57,0,0,0);CHECK(pid>=0);if(!pid){CHECK(C(1,fd,"BAD",3)==-13);return 0;}
  CHECK(C(61,pid,&status,0)==pid && status==0 && !C(3,fd,0,0));
  CHECK(!call(157,0x46534e53,0,0,0,0,0) && C(2,"/home/share/project/source.c",0,0)==-13);
 }else if(eq(argv[1],"exec")){
  fd=C(2,"/home/share/project/source.c",2,0);CHECK(fd==3);
  av[0]=(char *)"/worker";av[1]=(char *)"worker";av[2]=argv[2];av[3]=0;
  CHECK(C(59,"/worker",av,ep)==0);return 98;
 }else if(eq(argv[1],"worker")){
  CHECK(C(1,3,"BAD",3)==-13 && content("/home/share/project/source.c",argv[2]));
  CHECK(C(2,"/home/share/new",0102,0600)==-13);
  av[0]=(char *)"/privileged";av[1]=(char *)"again";av[2]=argv[2];av[3]=0;
  C(59,"/privileged",av,ep);return 97;
 }else if(eq(argv[1],"again")){
  CHECK(C(1,3,"BAD",3)==-13 && C(2,"/home/share/new",0102,0600)==-13);
 }else if(eq(argv[1],"revocation")){
  fd=C(2,"/home/share/project/source.c",2,0);CHECK(fd>=0 && C(0,fd,b,1)==1);
  other=C(2,"/var/admin/token",1,0);CHECK(other>=0 && C(1,other,"0",1)==1);
  CHECK(C(0,fd,b,1)==-13 && C(1,fd,"BAD",3)==-13 && C(5,fd,st,0)==-13);
  CHECK(!C(3,fd,0,0) && !C(3,other,0,0));
 }else if(eq(argv[1],"denials")){
  CHECK(C(82,"/home","/home-new",0)==-16 && C(84,"/home/share",0,0)==-16);
  CHECK(C(86,"/home/share/project/source.c","/tmp/alias",0)==-18);
  CHECK(C(88,"/etc/passwd","/home/share/escape",0)==-95);
  CHECK(!C(88,"/home/share/project/source.c","/tmp/link",0) && content("/tmp/link",argv[2]) && !C(87,"/tmp/link",0,0));
  CHECK(content("/home/share/project/source.c",argv[2]));
  CHECK(C(2,"/home/share/../../dev/host-secret",0,0)<0);
  CHECK(C(2,"/home/share/project/source.c",01000,0)==-22);
  fd=C(2,"/home/share/project/source.c",2,0);CHECK(fd>=0 && C(77,fd,65537,0)==-27 && !C(3,fd,0,0));
 }else if(eq(argv[1],"rename-failure")){
  fd=make("/home/share/first","first");CHECK(fd>=0 && !C(3,fd,0,0));fd=make("/home/share/second","second");CHECK(fd>=0 && !C(3,fd,0,0));
  n=C(82,"/home/share/first","/home/share/second",0);
  if(n==-17)CHECK(content("/home/share/first","first") && content("/home/share/second","second"));
  else CHECK(!n && content("/home/share/second","first"));
 }else if(eq(argv[1],"permissions")){
  CHECK(C(21,"/home/share/missing",0,0)==-2);
  CHECK(!C(90,"/home/share/project/source.c",0,0));
  CHECK(C(2,"/home/share/project/source.c",0,0)==-13 && C(76,"/home/share/project/source.c",0,0)==-13);
  CHECK(!C(90,"/home/share/project/source.c",0640,0));
  dir=C(2,"/home/share/project",0200000,0);CHECK(dir>=0 && !C(90,"/home/share/project",0500,0));
  CHECK(C(2,"/home/share/project/new",0102,0600)==-13 && C(87,"/home/share/project/source.c",0,0)==-13);
  CHECK(!C(90,"/home/share/project",0,0) && C(81,dir,0,0)==-13);
  CHECK(!C(90,"/home/share/project",0700,0) && !C(3,dir,0,0));
 }else if(eq(argv[1],"symlink-routes")){
  CHECK(!C(88,"/home/share/must-not-exist","/tmp/missing",0));
  CHECK(C(83,"/tmp/missing",0700,0)==-17 && C(4,"/home/share/must-not-exist",st,0)==-2);
  CHECK(!C(88,"/home/share/project","/tmp/directory-link",0));
  CHECK(C(82,"/tmp/directory-link/","/tmp/new",0)==-20 && C(84,"/tmp/directory-link/",0,0)==-20);
  CHECK(!C(4,"/home/share/project",st,0));
 }else if(eq(argv[1],"dir-inodes")){
  U dot,parent,actual;CHECK(!C(4,"/home/share",st,0));parent=st[1];
  dir=C(2,"/home/share/project",0200000,0);CHECK(dir>=0 && !C(5,dir,st,0));actual=st[1];
  n=C(217,dir,b,256);CHECK(n>=48);dot=*(U *)b;CHECK(dot==actual && *(U *)(b+24)==parent);
 }else if(eq(argv[1],"lifetime")){
  for(n=0;n<200;n++){fd=C(2,"/home/share/project/source.c",0,0);CHECK(fd>=0);other=C(32,fd,0,0);CHECK(other>=0 && !C(3,fd,0,0) && C(0,other,b,1)==1 && !C(3,other,0,0));}
 }else if(eq(argv[1],"sync")){
  fd=C(2,"/home/share/project/source.c",2,0);CHECK(fd>=0);
  n=C(74,fd,0,0);CHECK(n==0 || n==-95);CHECK(!C(3,fd,0,0));
 }else if(eq(argv[1],"eof")){
  fd=C(2,"/home/share/project/source.c",0,0);CHECK(fd>=0 && C(8,fd,65536,0)==65536 && C(0,fd,b,255)==0);
  CHECK(call(17,fd,(long)b,255,65536,0,0)==0 && !C(3,fd,0,0));
 }else if(eq(argv[1],"positioned")){
  fd=C(2,"/home/share/project/source.c",2,0);CHECK(fd>=0);
  CHECK(call(17,fd,(long)b,1,1,0,0)==1 && b[0]==argv[2][1] && C(8,fd,0,1)==0);
  CHECK(call(18,fd,(long)"X",1,1,0,0)==1 && C(8,fd,0,1)==0);
  CHECK(!C(77,fd,1,0) && !C(3,fd,0,0));
 }else if(eq(argv[1],"hidden")){
  dir=C(2,"/home",0200000,0);CHECK(dir>=0);
  CHECK(!call(157,0x46534e53,0,0,0,0,0));
  n=C(217,dir,b,256);CHECK(n>0);
  for(fd=0;fd+6<=n;fd++)CHECK(!(b[fd]=='s' && b[fd+1]=='h' && b[fd+2]=='a' && b[fd+3]=='r' && b[fd+4]=='e' && !b[fd+5]));
  CHECK(C(2,"/home/share",0,0)==-13);
 }else if(eq(argv[1],"alias")){
  fd=C(2,"/var/peer/project/source.c",02002,0);CHECK(fd>=0 && C(1,fd,"!",1)==1 && !C(3,fd,0,0));
  fd=C(2,"/home/share/project/source.c",0,0);CHECK(fd>=0);n=C(0,fd,b,255);CHECK(n==(long)len(argv[2])+1 && b[n-1]=='!');
 }else if(eq(argv[1],"host-links")){
  CHECK(C(2,"/home/share/escape/secret",0,0)<0 && C(2,"/home/share/leaf",0,0)<0);
 }else if(eq(argv[1],"oversized")){
  CHECK(C(2,"/home/share/large",01002,0600)==-27);
 }else if(eq(argv[1],"quota")){
  for(n=0;n<32;n++){char name[32]="/home/share/n00";name[13]=(char)('0'+n/10);name[14]=(char)('0'+n%10);fd=make(name,"x");CHECK(fd>=0 && !C(3,fd,0,0));}
  CHECK(C(2,"/home/share/full",0102,0600)==-28);
 }else if(eq(argv[1],"absent")){
  CHECK(C(2,"/home/share/project/source.c",0,0)<0);
 }else if(eq(argv[1],"fault")){
  fd=make("/home/share/completed",argv[2]);CHECK(fd>=0 && !C(3,fd,0,0));for(;;)__asm__ volatile("nop");
 }else return 99;
 print("FLEX_MOUNT_OK ");print(argv[1]);print("\n");print(argv[2]);print("\n");return 0;
}
