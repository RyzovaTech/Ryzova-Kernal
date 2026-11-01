/* SPDX-License-Identifier: AGPL-3.0-only */
/* Resource-profile probes: compiled on Windows, bounds are specific to Flex. */
#if !defined(_WIN64) || !defined(W6_CASE)
#error Windows AMD64 and W6_CASE required
#endif
typedef unsigned long DWORD;
typedef unsigned long long SIZE_T;
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
__declspec(noreturn) void flex_entry(void) {
    HANDLE file;DWORD value=0x12345678UL,n=0,readback=0;
    file=CreateFileW(path,0xc0000000UL,3,(void *)0,1,0x80,(HANDLE)0);
    if(file==(HANDLE)(~(SIZE_T)0) || !WriteFile(file,&value,4,&n,(void *)0) || n!=4 || !CloseHandle(file))ExitProcess(107);
    file=CreateFileW(path,0x80000000UL,3,(void *)0,3,0x80,(HANDLE)0);
    if(file==(HANDLE)(~(SIZE_T)0) || !ReadFile(file,&readback,4,&n,(void *)0) || n!=4 || readback!=value || !CloseHandle(file))ExitProcess(108);
    ExitProcess(37);
}
#endif
