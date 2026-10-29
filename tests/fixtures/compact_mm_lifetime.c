/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
static volatile long value=7;
static int ready[2],done[2],first[2],second[2];
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
 __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
static __attribute__((noreturn)) void bye(long code){C(60,code,0,0);__asm__ volatile("ud2");__builtin_unreachable();}
long app_main(long argc,char **argv,char **env)
{
 long parent,p1,p2,child,i;int status;char byte;U n;
 (void)env;CHECK(argc==2);
 CHECK(!C(22,ready,0,0) && !C(22,done,0,0) && !C(22,first,0,0) && !C(22,second,0,0));
 p1=C(57,0,0,0);CHECK(p1>=0);
 if(!p1){
  parent=C(39,0,0,0);child=C(58,0,0,0);CHECK(child>=0);
  if(!child){
   CHECK(C(1,ready[1],"R",1)==1 && !C(62,parent,9,0));
   CHECK(C(0,first[0],&byte,1)==1);byte=value==7?'Y':'N';CHECK(C(1,done[1],&byte,1)==1);bye(0);
  }
  bye(99);
 }
 CHECK(C(0,ready[0],&byte,1)==1 && byte=='R');CHECK(C(61,p1,&status,0)==p1 && (status&127)==9);
 p2=C(57,0,0,0);CHECK(p2>=0);
 if(!p2){
  value=99;child=C(58,0,0,0);CHECK(child>=0);
  if(!child){
   CHECK(C(1,ready[1],"S",1)==1 && C(0,second[0],&byte,1)==1);
   byte=value==99?'Z':'B';CHECK(C(1,done[1],&byte,1)==1);bye(0);
  }
  value=123;CHECK(C(61,child,&status,0)==child && !status);bye(0);
 }
 CHECK(C(0,ready[0],&byte,1)==1 && byte=='S');CHECK(C(1,first[1],"G",1)==1);
 CHECK(C(0,done[0],&byte,1)==1 && byte=='Y');for(i=0;i<10;i++)C(24,0,0,0);
 CHECK(C(1,second[1],"G",1)==1 && C(0,done[0],&byte,1)==1 && byte=='Z');
 CHECK(C(61,p2,&status,0)==p2 && !status);
 CHECK(C(1,1,"FLEX_MM_LIFETIME_OK\n",20)==20);
 for(n=0;argv[1][n];n++);CHECK(C(1,1,argv[1],n)==(long)n && C(1,1,"\n",1)==1);return 0;
}
