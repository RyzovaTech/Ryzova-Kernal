/* SPDX-License-Identifier: AGPL-3.0-only */
/* No CRT: all nine W3 imports must behave before the success markers appear. */
#if !defined(_WIN64)
#error Windows AMD64 target required
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
IMPORT DWORD __stdcall GetLastError(void);
IMPORT void __stdcall SetLastError(DWORD);
IMPORT WCHAR *__stdcall GetCommandLineW(void);
IMPORT DWORD __stdcall GetEnvironmentVariableW(const WCHAR *,WCHAR *,DWORD);
IMPORT void *__stdcall VirtualAlloc(void *,SIZE_T,DWORD,DWORD);
IMPORT BOOL __stdcall VirtualFree(void *,SIZE_T,DWORD);
typedef char dword_32[(sizeof(DWORD)==4)?1:-1];
typedef char pointer_64[(sizeof(void *)==8)?1:-1];
static const WCHAR variable[]={'F','L','E','X','_','W','3','_','P','R','O','B','E',0};
static const char output[]="FLEX_WINDOWS_W3_OK\n";
static const char error_output[]="FLEX_WINDOWS_W3_STDERR\n";
__declspec(noreturn) void flex_entry(void)
{
    WCHAR buffer[16];WCHAR *command;volatile DWORD *memory;DWORD written=0,n,i;int found=0;
    SetLastError(0x76543210UL);
    if(GetLastError()!=0x76543210UL)ExitProcess(101);
    command=GetCommandLineW();
    if(!command)ExitProcess(102);
    /* Launcher-specific executable paths differ; require the declared argument. */
    for(i=0;i<1024 && command[i];i++) {
        if(command[i]=='-' && command[i+1]=='-' && command[i+2]=='w' && command[i+3]=='3' && command[i+4]=='-' && command[i+5]=='t' && command[i+6]=='e' && command[i+7]=='s' && command[i+8]=='t'){found=1;break;}
    }
    if(!found)ExitProcess(103);
    n=GetEnvironmentVariableW(variable,(WCHAR *)0,0);
    if(n!=6)ExitProcess(104);
    if(GetEnvironmentVariableW(variable,buffer,16)!=5 || buffer[0]!='r' || buffer[1]!='e' || buffer[2]!='a' || buffer[3]!='d' || buffer[4]!='y' || buffer[5])ExitProcess(105);
    memory=(volatile DWORD *)VirtualAlloc((void *)0,4096,0x3000,4);
    if(!memory || memory[0]!=0)ExitProcess(106);
    memory[0]=0x13579bdfUL;
    if(!VirtualFree((void *)memory,4096,0x4000))ExitProcess(107);
    if(VirtualAlloc((void *)memory,4096,0x1000,4)!=(void *)memory || memory[0]!=0)ExitProcess(108);
    memory[0]=0x12345678UL;
    if(memory[0]!=0x12345678UL || !VirtualFree((void *)memory,0,0x8000))ExitProcess(109);
    if(!WriteFile(GetStdHandle((DWORD)-11),output,(DWORD)(sizeof(output)-1),&written,(void *)0) || written!=sizeof(output)-1)ExitProcess(110);
    if(!WriteFile(GetStdHandle((DWORD)-12),error_output,(DWORD)(sizeof(error_output)-1),&written,(void *)0) || written!=sizeof(error_output)-1)ExitProcess(111);
    ExitProcess(0x12345678UL);
}
