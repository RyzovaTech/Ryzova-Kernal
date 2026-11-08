/* SPDX-License-Identifier: GPL-3.0-only */
/* Resource-profile probes: compiled on Windows, bounds are specific to Flex. */
#if !defined(_WIN64) || !defined(W6_CASE)
#error Windows AMD64 and W6_CASE required
#endif
typedef unsigned long DWORD;
typedef unsigned long long SIZE_T;
typedef long long LONGLONG;
typedef unsigned short WCHAR;
typedef void *HANDLE;
typedef int BOOL;
#define IMPORT __declspec(dllimport)
IMPORT __declspec(noreturn) void __stdcall ExitProcess(DWORD);
IMPORT HANDLE __stdcall GetStdHandle(DWORD);
IMPORT BOOL __stdcall WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT BOOL __stdcall ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
IMPORT HANDLE __stdcall CreateFileW(const WCHAR *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
IMPORT BOOL __stdcall CloseHandle(HANDLE);
IMPORT BOOL __stdcall GetFileSizeEx(HANDLE,LONGLONG *);
IMPORT BOOL __stdcall SetFilePointerEx(HANDLE,LONGLONG,LONGLONG *,DWORD);
IMPORT DWORD __stdcall GetLastError(void);
IMPORT void *malloc(SIZE_T);
IMPORT int *_errno(void);
#if W6_CASE == 1
__declspec(noreturn) void flex_entry(void) {
    void *a=malloc(1048576);if(!a)ExitProcess(101);
    if(malloc(1)!=(void *)0 || *_errno()!=12)ExitProcess(102);
    ExitProcess(37);
}
#elif W6_CASE == 2
__declspec(noreturn) void flex_entry(void) {
    void *a=malloc(65537);DWORD n=99;if(!a)ExitProcess(103);
    if(WriteFile(GetStdHandle((DWORD)-11),a,65537,&n,(void *)0) || n!=0 || GetLastError()!=87)ExitProcess(104);
    ExitProcess(37);
}
#elif W6_CASE == 3
static const WCHAR path[]={'q','u','o','t','a','.','b','i','n',0};
__declspec(noreturn) void flex_entry(void) {
    HANDLE file;DWORD i;
    for(i=0;i<30;i++) {
        file=CreateFileW(path,0xc0000000UL,3,(void *)0,4,0x80,(HANDLE)0);
        if(file==(HANDLE)(~(SIZE_T)0))ExitProcess(105);
    }
    file=CreateFileW(path,0xc0000000UL,3,(void *)0,4,0x80,(HANDLE)0);
    if(file!=(HANDLE)(~(SIZE_T)0) || GetLastError()!=4)ExitProcess(106);
    ExitProcess(37);
}
#elif W6_CASE == 4
static const WCHAR path[]={'r','a','m','.','b','i','n',0};
static const WCHAR upper[]={'R','A','M','.','B','I','N',0};
__declspec(noreturn) void flex_entry(void) {
    HANDLE file,conflict;DWORD value=0x12345678UL,n=0,readback=0;LONGLONG size=0,position=0;
    file=CreateFileW(path,0xc0000000UL,0,(void *)0,1,0x80,(HANDLE)0);
    if(file==(HANDLE)(~(SIZE_T)0) || !WriteFile(file,&value,4,&n,(void *)0) || n!=4)ExitProcess(107);
    conflict=CreateFileW(upper,0xc0000000UL,3,(void *)0,2,0x80,(HANDLE)0);
    if(conflict!=(HANDLE)(~(SIZE_T)0) || GetLastError()!=32)ExitProcess(109);
    if(!GetFileSizeEx(file,&size) || size!=4)ExitProcess(110);
    if(!SetFilePointerEx(file,-1,&position,2) || position!=3)ExitProcess(111);
    if(!SetFilePointerEx(file,-3,&position,1) || position!=0)ExitProcess(112);
    if(!ReadFile(file,&readback,4,&n,(void *)0) || n!=4 || readback!=value || !CloseHandle(file))ExitProcess(113);
    file=CreateFileW(upper,0x80000000UL,3,(void *)0,3,0x80,(HANDLE)0);
    if(file==(HANDLE)(~(SIZE_T)0) || !SetFilePointerEx(file,0,&position,0) || position!=0)ExitProcess(114);
    if(!ReadFile(file,&readback,4,&n,(void *)0) || n!=4 || readback!=value)ExitProcess(115);
    if(!ReadFile(file,&readback,4,&n,(void *)0) || n!=0 || !CloseHandle(file))ExitProcess(116);
    if(CloseHandle(file) || GetLastError()!=6)ExitProcess(117);
    ExitProcess(37);
}
#endif
