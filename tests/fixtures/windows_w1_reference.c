/* SPDX-License-Identifier: AGPL-3.0-only */
/* Native Windows reference fixture; no CRT and no proprietary binary is shipped. */
#if !defined(_WIN64)
#error This fixture requires the Windows AMD64 compiler target
#endif
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(DWORD);
typedef char require_dword_32[(sizeof(DWORD)==4)?1:-1];
typedef char require_pointer_64[(sizeof(void *)==8)?1:-1];
__declspec(noreturn) void flex_entry(void)
{
    static const char message[]="FLEX_WINDOWS_REFERENCE_OK\n";
    DWORD written=0;
    HANDLE output=GetStdHandle((DWORD)-11);
    if(!output || output==(HANDLE)(~(unsigned long long)0))ExitProcess(91);
    if(!WriteFile(output,message,(DWORD)(sizeof(message)-1),&written,(void *)0) || written!=sizeof(message)-1)ExitProcess(92);
    ExitProcess(37);
}
