/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
 __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static int equal(const char *a,const char *b){while(*a && *a==*b){a++;b++;}return *a==*b;}
static U length(const char *s){U n=0;while(s[n])n++;return n;}
static void print(const char *s){C(1,1,s,length(s));}
long app_main(long argc,char **argv,char **env)
{
 long fd,n;char bytes[256];U st[18];(void)env;CHECK(argc==3);
 if(equal(argv[1],"create") || equal(argv[1],"fault")){
  {int pair[2];U socket_stat[18],directory_stat[18];long directory;
   directory=C(2,"/tmp",0,0);CHECK(directory>=0 && !C(5,directory,directory_stat,0));
   CHECK(!call(53,1,1,0,(long)pair,0,0) && !C(5,pair[0],socket_stat,0));
   CHECK(socket_stat[0]!=directory_stat[0] || socket_stat[1]!=directory_stat[1]);
   CHECK(!C(3,pair[0],0,0) && !C(3,pair[1],0,0) && !C(3,directory,0,0));}
  CHECK(!C(83,"/tmp/state",0700,0));fd=C(2,"/tmp/state/data",0101,0600);CHECK(fd>=0);
  CHECK(C(1,fd,argv[2],length(argv[2]))==(long)length(argv[2]) && !C(3,fd,0,0));
  fd=C(2,"/tmp/removed",0101,0600);CHECK(fd>=0 && !C(87,"/tmp/removed",0,0));
  if(equal(argv[1],"fault"))for(;;)__asm__ volatile("nop");
 }else if(equal(argv[1],"verify")){
  fd=C(2,"/tmp/state/data",0,0);CHECK(fd>=0 && !C(5,fd,st,0));
  CHECK((((unsigned int *)st)[6]&0777)==0600);n=C(0,fd,bytes,sizeof bytes-1);CHECK(n>=0);bytes[n]=0;CHECK(equal(bytes,argv[2]));
  CHECK(C(2,"/tmp/removed",0,0)==-2);
 }else if(equal(argv[1],"append")){
  fd=C(2,"/tmp/state/data",02001,0);CHECK(fd>=0 && C(1,fd,"!",1)==1 && !C(3,fd,0,0));
 }else if(equal(argv[1],"rename")){
  CHECK(!C(82,"/tmp/state/data","/tmp/state/renamed",0));fd=C(2,"/tmp/state/renamed",0,0);CHECK(fd>=0);
  CHECK(!C(87,"/tmp/state/renamed",0,0) && !C(3,fd,0,0) && !C(84,"/tmp/state",0,0));
 }else if(equal(argv[1],"empty")){
  CHECK(C(2,"/tmp/state/data",0,0)==-2 && C(2,"/tmp/state",0,0)==-2);
 }else return 99;
 print("FLEX_PERSISTENCE_OK ");print(argv[1]);print("\n");print(argv[2]);print("\n");return 0;
}
