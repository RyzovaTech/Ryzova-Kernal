/* SPDX-License-Identifier: GPL-3.0-only */
/* Six frozen MSVC workloads. Only explicit kernel32/UCRT exports, no CRT startup. */
#if !defined(_WIN64) || !defined(W5_CASE)
#error Windows AMD64 target and W5_CASE required
#endif
typedef unsigned long DWORD;
typedef unsigned long long SIZE_T;
typedef unsigned short WCHAR;
typedef void *HANDLE;
typedef int BOOL;
#define IMPORT __declspec(dllimport)
IMPORT HANDLE __stdcall GetStdHandle(DWORD);
IMPORT BOOL __stdcall WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT __declspec(noreturn) void __stdcall ExitProcess(DWORD);
IMPORT void *memcpy(void *,const void *,SIZE_T);
IMPORT void *memmove(void *,const void *,SIZE_T);
IMPORT void *memset(void *,int,SIZE_T);
IMPORT int memcmp(const void *,const void *,SIZE_T);
IMPORT SIZE_T strlen(const char *);
IMPORT int strcmp(const char *,const char *);
IMPORT int strncmp(const char *,const char *,SIZE_T);
IMPORT SIZE_T wcslen(const WCHAR *);
IMPORT void *malloc(SIZE_T);
IMPORT void *calloc(SIZE_T,SIZE_T);
IMPORT void *realloc(void *,SIZE_T);
IMPORT void free(void *);
IMPORT int *_errno(void);
#if W5_CASE <= 3
static __declspec(noreturn) void success(const char *text,DWORD bytes,DWORD code)
{
    DWORD written=0;
    if(!WriteFile(GetStdHandle((DWORD)-11),text,bytes,&written,(void *)0) || written!=bytes)ExitProcess(199);
    ExitProcess(code);
}
#endif
#if W5_CASE == 1
static const WCHAR wide[]={'a',0xd83d,0xde00,'b',0};
__declspec(noreturn) void flex_entry(void)
{
    char a[64],b[64];SIZE_T n;
    if(memset(a,0,64)!=a || memset(b,0,64)!=b)ExitProcess(101);
    if(memcpy(a,"alpha",6)!=a || strlen(a)!=5)ExitProcess(102);
    if(memmove(a+2,a,6)!=a+2 || memcmp(a,"alalpha",8)!=0)ExitProcess(103);
    if(memcpy(b,"alpine",7)!=b || strcmp("alpha",b)>=0 || strncmp("alpha",b,3)!=0)ExitProcess(104);
    n=wcslen(wide);if(n!=4)ExitProcess(105);
    success("FLEX_W5_BUFFERS_OK\n",(DWORD)(sizeof("FLEX_W5_BUFFERS_OK\n")-1),0x34567891UL);
}
#elif W5_CASE == 2
__declspec(noreturn) void flex_entry(void)
{
    char *zero=(char *)calloc(16,4),*p,*q;SIZE_T i;
    if(!zero)ExitProcess(111);
    for(i=0;i<64;i++)if(zero[i])ExitProcess(112);
    p=(char *)malloc(32);if(!p)ExitProcess(113);
    memset(p,'x',32);q=(char *)realloc(p,8192);if(!q)ExitProcess(114);
    memset(zero,'x',32);if(memcmp(q,zero,32)!=0)ExitProcess(115);
    *_errno()=0;
    if(calloc(~(SIZE_T)0,2)!=(void *)0 || *_errno()!=12)ExitProcess(116);
    if(memcmp(q,zero,32)!=0)ExitProcess(117);
    free(q);free(zero);
    success("FLEX_W5_HEAP_OK\n",(DWORD)(sizeof("FLEX_W5_HEAP_OK\n")-1),0x34567892UL);
}
#elif W5_CASE == 3
volatile SIZE_T input_a=0x8123456789abcdefULL,input_b=0x0fedcba987654321ULL;
volatile long long signed_input=-1234567890123LL,signed_divisor=97;
__declspec(noreturn) void flex_entry(void)
{
    SIZE_T hash=0xcbf29ce484222325ULL,a=input_a,b=input_b,i;
    long long numerator=signed_input,divisor=signed_divisor;
    for(i=0;i<64;i++) {
        hash^=a>>(i&63);hash*=0x100000001b3ULL;
        hash=(hash>>7)|(hash<<57);hash+=b/(i+1);
    }
    if(hash!=0x8d4c2b0deea4b991ULL || numerator/divisor!=-12727504021LL || numerator%divisor!=-86)ExitProcess(121);
    success("FLEX_W5_INTEGER_OK\n",(DWORD)(sizeof("FLEX_W5_INTEGER_OK\n")-1),0x34567893UL);
}
#elif W5_CASE == 4
volatile SIZE_T divisor_zero=0;
__declspec(noreturn) void flex_entry(void) { SIZE_T result=123/divisor_zero;ExitProcess((DWORD)result); }
#elif W5_CASE == 5
volatile DWORD *volatile invalid_address=(volatile DWORD *)0;
__declspec(noreturn) void flex_entry(void) { DWORD result=*invalid_address;ExitProcess(result); }
#elif W5_CASE == 6
void __ud2(void);
#pragma intrinsic(__ud2)
__declspec(noreturn) void flex_entry(void) { __ud2(); }
#else
#error Unsupported W5_CASE
#endif
