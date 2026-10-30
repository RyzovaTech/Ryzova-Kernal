/* SPDX-License-Identifier: AGPL-3.0-only */
typedef unsigned long U;
/* Force PT_TLS so the extended process loader is selected; freestanding code
 * does not use this TLS object and does not require libc TLS initialization. */
__thread int extended_profile=7;
static unsigned char bytes[32];
static __attribute__((always_inline)) inline long call(long nr,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;long out;
 __asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#define C(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do{if(!(x))return __LINE__;}while(0)
long app_main(long argc,char **argv,char **env)
{
 long fd,map,anon;U i;(void)env;CHECK(argc==2);
 fd=C(2,"/library",0,0);CHECK(fd>=0);
 CHECK(call(9,0,4096,7,2,fd,0)==-1);
 map=call(9,0,4096,5,2,fd,0);CHECK(map>0 && *(unsigned char *)map==127);
 CHECK(C(10,map,4096,1)==0 && C(10,map,4096,5)==0);
 CHECK(C(10,map,4096,3)==0 && C(10,map,4096,5)==-1);
 CHECK(call(9,((U)app_main)&~4095UL,4096,1,2|16,fd,0)==-22);
 CHECK(C(11,map,4096,0)==0 && C(1,1,map,1)==-14);
 anon=call(9,0,4096,3,34,-1,0);CHECK(anon>0 && C(10,anon,4096,5)==-1);
 CHECK(call(9,0,4096,5,34,-1,0)==-1);
 CHECK(C(318,bytes,16,0)==16 && C(318,0,0,0)==0 && C(318,1,16,0)==-14);
 CHECK(C(324,0,0,0)==24 && C(324,8,0,0)==-1 && C(324,16,0,0)==0 && C(324,8,0,0)==0);
 CHECK(C(1,1,"FLEX_MEMORY_OK\n",15)==15);
 for(i=0;argv[1][i];i++);CHECK(C(1,1,argv[1],i)==(long)i && C(1,1,"\n",1)==1);return 0;
}
