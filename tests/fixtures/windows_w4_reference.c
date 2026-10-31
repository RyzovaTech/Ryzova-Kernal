/* SPDX-License-Identifier: AGPL-3.0-only */
/* Freestanding Windows AMD64 file-I/O reference; no CRT or copied SDK DLLs. */
#if !defined(_WIN64)
#error Windows AMD64 target required
#endif
typedef unsigned long DWORD;
typedef long long LONGLONG;
typedef unsigned short WCHAR;
typedef void *HANDLE;
typedef int BOOL;
#define IMPORT __declspec(dllimport)
IMPORT HANDLE __stdcall CreateFileW(const WCHAR *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
IMPORT BOOL __stdcall WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT BOOL __stdcall ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
IMPORT BOOL __stdcall SetFilePointerEx(HANDLE,LONGLONG,LONGLONG *,DWORD);
IMPORT BOOL __stdcall GetFileSizeEx(HANDLE,LONGLONG *);
IMPORT BOOL __stdcall FlushFileBuffers(HANDLE);
IMPORT BOOL __stdcall CloseHandle(HANDLE);
IMPORT DWORD __stdcall GetLastError(void);
IMPORT HANDLE __stdcall GetStdHandle(DWORD);
IMPORT __declspec(noreturn) void __stdcall ExitProcess(DWORD);
static const WCHAR path[]={'p','a','y','l','o','a','d','.','b','i','n',0};
static const WCHAR upper[]={'P','A','Y','L','O','A','D','.','B','I','N',0};
static const char data[]="FLEX_WINDOWS_W4_FILE_OK\n";
static const char output[]="FLEX_WINDOWS_W4_OK\n";
__declspec(noreturn) void flex_entry(void)
{
    HANDLE file;DWORD count=0,i;LONGLONG size=0,position=0;char buffer[64];
    file=CreateFileW(path,0xc0000000UL,3,(void *)0,1,0x80,(HANDLE)0);
    if(file==(HANDLE)(~(unsigned long long)0))ExitProcess(101);
    if(!WriteFile(file,data,(DWORD)(sizeof(data)-1),&count,(void *)0) || count!=sizeof(data)-1)ExitProcess(102);
    if(!FlushFileBuffers(file))ExitProcess(103);
    if(!GetFileSizeEx(file,&size) || size!=(LONGLONG)(sizeof(data)-1))ExitProcess(104);
    if(!SetFilePointerEx(file,0,&position,0) || position!=0)ExitProcess(105);
    if(!ReadFile(file,buffer,64,&count,(void *)0) || count!=sizeof(data)-1)ExitProcess(106);
    for(i=0;i<count;i++)if(buffer[i]!=data[i])ExitProcess(107);
    if(!ReadFile(file,buffer,64,&count,(void *)0) || count!=0)ExitProcess(108);
    if(!SetFilePointerEx(file,-3,&position,2) || position!=(LONGLONG)(sizeof(data)-4))ExitProcess(109);
    if(!SetFilePointerEx(file,1,&position,1) || position!=(LONGLONG)(sizeof(data)-3))ExitProcess(110);
    if(!SetFilePointerEx(file,(LONGLONG)(sizeof(data)+2),&position,0))ExitProcess(111);
    if(!WriteFile(file,"!",1,&count,(void *)0) || count!=1 || !FlushFileBuffers(file))ExitProcess(112);
    if(!GetFileSizeEx(file,&size) || size!=(LONGLONG)(sizeof(data)+3) || !CloseHandle(file))ExitProcess(113);
    file=CreateFileW(upper,0x80000000UL,3,(void *)0,3,0x80,(HANDLE)0);
    if(file==(HANDLE)(~(unsigned long long)0))ExitProcess(114);
    if(!SetFilePointerEx(file,-4,(LONGLONG *)0,2) || !ReadFile(file,buffer,4,&count,(void *)0) || count!=4)ExitProcess(115);
    if(buffer[0] || buffer[1] || buffer[2] || buffer[3]!='!' || !CloseHandle(file))ExitProcess(116);
    if(CloseHandle(file) || GetLastError()!=6)ExitProcess(117);
    file=CreateFileW(path,0xc0000000UL,3,(void *)0,1,0x80,(HANDLE)0);
    if(file!=(HANDLE)(~(unsigned long long)0) || GetLastError()!=80)ExitProcess(118);
    if(!WriteFile(GetStdHandle((DWORD)-11),output,(DWORD)(sizeof(output)-1),&count,(void *)0) || count!=sizeof(output)-1)ExitProcess(119);
    ExitProcess(0x23456789UL);
}
