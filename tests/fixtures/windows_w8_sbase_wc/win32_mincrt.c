/* SPDX-License-Identifier: AGPL-3.0-only
 * W8 explicitly bounded, original Win32 ABI glue for the unmodified
 * MIT sbase wc.c text utility. NO MSVCRT/UCRT, host syscall forwarding,
 * dynamic imports, Unicode claim, arbitrary filesystem or Win32 ABI spoof.
 * This is an opt-in research PE candidate, not native QEMU verification.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "upstream/utf.h"

/* The source owns the public 'main'; no C runtime initialization. */
extern int main(int,char **);
char *argv0;
static unsigned char stdin_ref,stdout_ref,stderr_ref;
static HANDLE output_handle(void) { return GetStdHandle(STD_OUTPUT_HANDLE); }
static HANDLE error_handle(void) { return GetStdHandle(STD_ERROR_HANDLE); }

static void put_bytes(HANDLE out,const char *s,unsigned int n) {
    unsigned int off=0;
    while(off<n) {
        DWORD done=0;
        if(!WriteFile(out,s+off,(DWORD)(n-off),&done,0) || !done)
            ExitProcess(2);
        off+=(unsigned int)done;
    }
}
static void put_error(const char *s) {
    unsigned int n=0;while(s[n] && n<240)n++;
    if(n)put_bytes(error_handle(),s,n);
}
static void fail_ascii(void) {
    put_error("sbase wc: non-ASCII data unsupported by W8 bridge\n");
    ExitProcess(2);
}

FILE *cw_w8_stdin(void) { return (FILE *)&stdin_ref; }
FILE *cw_w8_stdout(void) { return (FILE *)&stdout_ref; }
FILE *cw_w8_stderr(void) { return (FILE *)&stderr_ref; }

/* No arbitrary path/file permissions; stdin-only candidate on purpose. */
FILE *cw_w8_fopen(const char *path,const char *mode) {
    (void)path;(void)mode;
    return 0;
}
int cw_w8_strcmp(const char *a,const char *b) {
    for(;*a && *a==*b;a++,b++);
    return (unsigned char)*a-(unsigned char)*b;
}
int cw_w8_putchar(int value) {
    char c=(char)value;put_bytes(output_handle(),&c,1);
    return (unsigned char)c;
}
static int put_string(const char *s) {
    int n=0;if(!s)return 0;
    while(s[n] && n<2048)n++;
    put_bytes(output_handle(),s,(unsigned int)n);
    return n;
}
static int put_decimal(size_t val) {
    char digits[32];int n=0,i;
    do { digits[n++]=(char)('0'+val%10);val/=10; } while(val && n<(int)sizeof(digits));
    for(i=n-1;i>=0;i--)cw_w8_putchar(digits[i]);
    return n;
}
/* Only formats in the unchanged sbase wc.c are permitted: %zu, %s and
 * single literal spaces. Unknown libc formatting fails closed. */
int cw_w8_printf(const char *format,...) {
    va_list ap;int n=0;const char *p;
    if(!format)ExitProcess(2);
    va_start(ap,format);
    for(p=format;*p;p++) {
        if(*p!='%')n+=(cw_w8_putchar(*p)>=0);
        else if(p[1]=='z' && p[2]=='u') {
            n+=put_decimal(va_arg(ap,size_t));p+=2;
        }else if(p[1]=='s') {
            n+=put_string(va_arg(ap,const char*));p++;
        }else ExitProcess(2);
    }
    va_end(ap);
    return n;
}
void eprintf(const char *fmt,...) {
    (void)fmt;put_error("sbase wc: unsupported argument or stream\n");
    ExitProcess(2);
}
void weprintf(const char *fmt,...) {
    (void)fmt;put_error("sbase wc: file arguments not authorized\n");
}
int fshut(FILE *stream,const char *name) {
    (void)stream;(void)name;return 0; /* every output uses unbuffered WriteFile */
}
int efgetrune(Rune *value,FILE *stream,const char *name) {
    unsigned char c;DWORD got=0;
    (void)name;
    if(!value || stream!=cw_w8_stdin())ExitProcess(2);
    if(!ReadFile(GetStdHandle(STD_INPUT_HANDLE),&c,1,&got,0))ExitProcess(2);
    if(got==0)return 0;
    if(c>=128)fail_ascii();
    *value=(Rune)c;
    return 1;
}
int isspacerune(Rune c) {
    return c==' ' || c=='\t' || c=='\n' ||
           c=='\r' || c=='\v' || c=='\f';
}
__declspec(noreturn) void cw_wc_entry(void) {
    char name[]="sbase-wc.exe";
    char *args[2]={name,0};
    int status=main(1,args);
    ExitProcess((UINT)status);
}
