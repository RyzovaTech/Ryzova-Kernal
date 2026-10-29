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
long app_main(long argc,char **argv,char **env)
{
 unsigned char address[16]={2,0,31,144,10,20,30,40},peer[16];unsigned int length=16;long fd,child,n;int status;char reply[8];(void)env;
 CHECK(argc==2);fd=C(41,2,1,0);CHECK(fd>=0);
 if(equal(argv[1],"no-grant")){CHECK(C(42,fd,address,16)==-101 && !C(3,fd,0,0));return 0;}
 if(equal(argv[1],"options-before")){int value=1;CHECK(!call(54,fd,1,9,(long)&value,4,0));CHECK(C(42,fd,address,16)==-95);return 0;}
 CHECK(!C(42,fd,address,16) && !C(52,fd,peer,&length) && length==16 && peer[4]==10 && peer[7]==40);
 if(equal(argv[1],"policy")){
  int value=1;CHECK(C(48,fd,1,0)==-95 && call(54,fd,6,1,(long)&value,4,0)==-95);
  CHECK(!C(48,fd,2,0) && C(0,fd,reply,1)==0 && call(44,fd,(long)"x",1,16384,0,0)==-32);return 0;
 }
 if(equal(argv[1],"fdshare")){
  child=C(57,0,0,0);CHECK(child>=0);
  if(!child){CHECK(C(1,fd,"ping",4)==4 && !C(3,fd,0,0));return 0;}
  CHECK(C(61,child,&status,0)==child && status==0);
 }else{
  n=equal(argv[1],"write-closed")?call(44,fd,(long)"ping",4,16384,0,0):C(1,fd,"ping",4);
  if(equal(argv[1],"write-closed")){CHECK(n==-32);return 0;}
  if(equal(argv[1],"write-error")){CHECK(n==-5);return 0;}
  CHECK(n==4);
 }
 n=C(0,fd,reply,4);
 if(equal(argv[1],"read-error")){CHECK(n==-104);return 0;}
 if(equal(argv[1],"eof")){CHECK(n==0);return 0;}
 CHECK(n==4 && reply[0]=='p' && reply[3]=='g' && !C(3,fd,0,0));return 0;
}
