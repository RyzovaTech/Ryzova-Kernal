/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../windows/runtime.h"
#include "m8_start.h"
#include "m8_fma.h"

#ifndef CW_PLAN9
#include <string.h>
#include <stdlib.h>
#endif

enum {
    Intel64 = 0x01000007, Arm64 = 0x0100000c,
    StackBase = 0x800000, StackBytes = Mac8StackBytes, StartBudget = 4096,
    Argv = 0x100, Envp = 0x1a0, LocaleEnv = 0x1d0, Args = 0x200, ArgLimit = 4096, GuardOffset = 8, StreamsOffset = 16, RuneOffset = 64, ErrnoOffset = 16, PathOffset = 64, PathBytes = 1024
};

typedef unsigned long long Word;
#define SERVICE_BASE (MAC8_BASE+Mac8Limit)
#define HEAP_BASE (SERVICE_BASE+Mac8ServiceBytes)
#define WRITABLE_BASE (HEAP_BASE+Mac8HeapBytes)
enum { ServiceExtent = Mac8ArenaBytes-Mac8StackBytes };
#define STREAM_HANDLE 0x18000ULL
#define INPUT_HANDLE (STREAM_HANDLE+48)
#define ERRNO_ADDRESS (WRITABLE_BASE+ErrnoOffset)

static Word
read_le(const unsigned char *data, unsigned int bytes)
{
    Word value = 0;
    unsigned int i;
    for(i=0; i<bytes; i++)
        value |= (Word)data[i] << (8*i);
    return value;
}

static void
write_le(unsigned char *data, unsigned int bytes, Word value)
{
    unsigned int i;
    for(i=0; i<bytes; i++)
        data[i] = value >> (8*i);
}

static Word
sign_extend(unsigned int value, unsigned int bits)
{
    Word range = (Word)1 << bits;
    return (Word)value - ((value & (range>>1)) ? range : 0);
}

static int
stack_span(Word addr, unsigned int count)
{
    return count <= StackBytes && addr >= StackBase && addr-StackBase <= StackBytes-count;
}

static const unsigned char *
guest_read(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
           Word at, unsigned int bytes, int services)
{
    if(mac8_access(plan, at, bytes, Mac8Read))
        return arena+(at-MAC8_BASE);
    if(stack_span(at, bytes))
        return stack+(at-StackBase);
    if(services && at>=SERVICE_BASE && bytes<=Mac8ServiceBytes &&
       at-SERVICE_BASE<=Mac8ServiceBytes-bytes)
        return arena+(at-MAC8_BASE);
    if(services && at>=HEAP_BASE && bytes<=Mac8HeapBytes+Mac8WritableBytes &&
       at-HEAP_BASE<=Mac8HeapBytes+Mac8WritableBytes-bytes)
        return arena+(at-MAC8_BASE);
    return 0;
}

static unsigned char *
guest_write(const Mac8Image *plan, unsigned char *arena, unsigned char *stack,
            Word at, unsigned int bytes, int services)
{
    if(mac8_access(plan, at, bytes, Mac8Write))
        return arena+(at-MAC8_BASE);
    if(stack_span(at, bytes))
        return stack+(at-StackBase);
    if(services && at>=HEAP_BASE && bytes<=Mac8HeapBytes+Mac8WritableBytes &&
       at-HEAP_BASE<=Mac8HeapBytes+Mac8WritableBytes-bytes)
        return arena+(at-MAC8_BASE);
    return 0;
}

static Word
resolve_data(const char *name)
{
    static const char *streams[] = {"___stdinp", "___stdoutp", "___stderrp"};
    unsigned int i;
    if(!strcmp(name, "___stack_chk_guard"))
        return SERVICE_BASE+GuardOffset;
    if(!strcmp(name, "__DefaultRuneLocale"))
        return SERVICE_BASE+RuneOffset;
    for(i=0; i<3; i++)
        if(!strcmp(name, streams[i]))
            return SERVICE_BASE+StreamsOffset+8*i;
    return 0;
}

static unsigned int
rune_type(unsigned int c)
{
    enum { Alpha = 0x100, Control = 0x200, Digit = 0x400, Graph = 0x800,
           Lower = 0x1000, Punct = 0x2000, Space = 0x4000, Upper = 0x8000,
           Hex = 0x10000, Blank = 0x20000, Print = 0x40000 };
    if(c>127)
        return 0;
    if(c<32 || c==127)
        return Control | (c>=9 && c<=13 ? Space : 0) | (c==9 ? Blank : 0);
    if(c==' ')
        return Space|Blank|Print;
    if(c>='0' && c<='9')
        return Graph|Print|Digit|Hex|(c-'0');
    if(c>='a' && c<='z')
        return Graph|Print|Alpha|Lower|(c<='f' ? Hex|(c-'a'+10) : 0);
    if(c>='A' && c<='Z')
        return Graph|Print|Alpha|Upper|(c<='F' ? Hex|(c-'A'+10) : 0);
    return Graph|Print|Punct;
}

static void
rune_locale(unsigned char *p)
{
    /* Darwin LP64 _RuneLocale has its three cached arrays at byte 60.
     * The pointer fields and uncached ranges stay zero in this C profile. */
    unsigned int c, lower, upper;
    memcpy(p, "RuneMagA", 8);
    memcpy(p+8, "NONE", 4);
    for(c=0; c<256; c++){
        lower = c>='A' && c<='Z' ? c+32 : c;
        upper = c>='a' && c<='z' ? c-32 : c;
        write_le(p+60+4*c, 4, rune_type(c));
        write_le(p+60+1024+4*c, 4, lower);
        write_le(p+60+2048+4*c, 4, upper);
    }
}

/* The only configured locale is C, including the default selected by
 * an empty string. A null pointer queries the current locale. */
static int
locale_call(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
            Word category, Word locale)
{
    const unsigned char *p;
    if((unsigned int)category!=0)
        return 0;
    if(!locale)
        return 1;
    p = guest_read(plan, arena, stack, locale, 1, 1);
    if(!p)
        return 0;
    if(!p[0])
        return 1;
    p = guest_read(plan, arena, stack, locale, 2, 1);
    return p && p[0]=='C' && p[1]==0;
}

static int
string_length(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
              Word address, unsigned int limit)
{
    unsigned int i;
    const unsigned char *p;
    for(i=0; i<limit; i++){
        p = guest_read(plan, arena, stack, address+i, 1, 1);
        if(!p)
            break;
        if(!*p)
            return i;
    }
    return -1;
}

enum { DirectArg, StackArgs, IntelVaList };

static int
format_guest(const Mac8Image *plan, const unsigned char *arena, const unsigned char *stack,
             Word format, Word arguments, int arg_kind, unsigned char *buf, unsigned int room)
{
    const unsigned char *p;
    unsigned char spec, digits[10];
    unsigned int i, count = 0, used = 0, gp, value, n;
    Word at, arg;
    int negative;
    for(i=0; i<=Mac8OutputLimit; i++){
        p = guest_read(plan, arena, stack, format+i, 1, 1);
        if(!p)
            return -1;
        if(!*p)
            return count;
        spec = *p;
        if(spec=='%'){
            p = guest_read(plan, arena, stack, format+(++i), 1, 1);
            if(!p)
                return -1;
            spec = *p;
            if(spec!='%'){
                if(arg_kind==DirectArg){
                    if(used)
                        return -1;
                    arg = arguments;
                }else{
                    at = arguments+8*used;
                    if(arg_kind==IntelVaList){
                        p = guest_read(plan, arena, stack, arguments, 24, 1);
                        if(!p)
                            return -1;
                        gp = read_le(p, 4);
                        if(gp>48 || gp%8)
                            return -1;
                        gp += 8*used;
                        at = gp<48 ? read_le(p+16, 8)+gp : read_le(p+8, 8)+(gp-48);
                    }
                    p = guest_read(plan, arena, stack, at, 8, 1);
                    if(!p)
                        return -1;
                    arg = read_le(p, 8);
                }
                used++;
                if(spec=='s'){
                    for(;; arg++){
                        p = guest_read(plan, arena, stack, arg, 1, 1);
                        if(!p)
                            return -1;
                        if(!*p)
                            break;
                        if(count==room)
                            return -1;
                        buf[count++] = *p;
                    }
                }else if(spec=='d' || spec=='i' || spec=='u'){
                    value = arg;
                    negative = spec!='u' && (value>>31);
                    if(negative)
                        value = 0U-value;
                    n = 0;
                    do {
                        digits[n++] = '0'+value%10;
                        value /= 10;
                    } while(value);
                    if(n+(unsigned int)negative>room-count)
                        return -1;
                    if(negative)
                        buf[count++] = '-';
                    while(n)
                        buf[count++] = digits[--n];
                }else
                    return -1;
                continue;
            }
        }
        if(count==room)
            return -1;
        buf[count++] = spec;
    }
    return -1;
}

enum { KeyLimit = 16, ExitLimit = 16 };
#define EXIT_RETURN 0x19010ULL
typedef struct Thread Thread;
struct Thread {
    Word values[KeyLimit];
    Word cleanup[ExitLimit], exit_sp;
    const unsigned char *input;
    const char *input_name;
    unsigned int input_bytes, input_offset;
    unsigned int allocated, closed, cleanup_count, input_open, input_eof;
};

static int
write_stream(Thread *thread, Mac8Stop *out, Word stream, const unsigned char *bytes, unsigned int count)
{
    unsigned char *buffer;
    unsigned int *used;
    if(stream==STREAM_HANDLE+16 && !(thread->closed&2)){
        buffer = out->stdout_data;
        used = &out->stdout_bytes;
    }else if(stream==STREAM_HANDLE+32 && !(thread->closed&4)){
        buffer = out->stderr_data;
        used = &out->stderr_bytes;
    }else
        return 0;
    if(count>Mac8OutputLimit-*used)
        return 0;
    memcpy(buffer+*used, bytes, count);
    *used += count;
    return 1;
}

/* Return 1 for a supported call, 0 for an unknown contract, and -1 for
 * a guest memory or allocation-ownership fault. Return 2 for guest exit. */
static int
service_call(const Mac8Image *plan, unsigned char *arena, unsigned char *stack,
             Mac8Heap *heap, const char *name, Word a0, Word a1, Word a2, Word a3, Word varargs,
             Word *result, Thread *thread, Mac8Stop *out)
{
    unsigned int offset, i;
    const unsigned char *left, *right;
    unsigned char *dest, formatted[Mac8OutputLimit];
    int count, zero = !strcmp(name, "_calloc");
    *result = 0;
    if(!strcmp(name, "_setlocale")){
        if(!locale_call(plan, arena, stack, a0, a1))
            return -1;
        *result = SERVICE_BASE;
        out->locale_calls++;
    }else if(!strcmp(name, "___error")){
        *result = ERRNO_ADDRESS;
    }else if(!strcmp(name, "_malloc") || zero){
        Word bytes = a0;
        if(zero)
            bytes = a1 && a0>Mac8HeapBytes/a1 ? Mac8HeapBytes+1 : a0*a1;
        offset = mac8_alloc(heap, bytes);
        if(offset!=Mac8HeapBytes){
            if(zero && bytes)
                memset(arena+(HEAP_BASE-MAC8_BASE)+offset, 0, bytes);
            *result = HEAP_BASE+offset;
        }else
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 12); /* ENOMEM */
        out->alloc_calls++;
    }else if(!strcmp(name, "_realloc")){
        if(!a0)
            offset = mac8_alloc(heap, a1);
        else if(a0<HEAP_BASE || a0-HEAP_BASE>=Mac8HeapBytes ||
                !mac8_resize(heap, arena+(HEAP_BASE-MAC8_BASE), a0-HEAP_BASE, a1, &offset))
            return -1;
        if(offset!=Mac8HeapBytes)
            *result = HEAP_BASE+offset;
        else
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 12);
        out->alloc_calls++;
    }else if(!strcmp(name, "_strdup") || !strcmp(name, "_strlen")){
        count = string_length(plan, arena, stack, a0, 65536);
        if(count<0)
            return -1;
        i = count;
        if(!strcmp(name, "_strlen")){
            *result = i;
            return 1;
        }
        left = guest_read(plan, arena, stack, a0, i+1, 1);
        if(!left)
            return -1;
        offset = mac8_alloc(heap, i+1);
        if(offset!=Mac8HeapBytes){
            dest = arena+(HEAP_BASE-MAC8_BASE)+offset;
            memmove(dest, left, i+1);
            *result = HEAP_BASE+offset;
        }else
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 12);
        out->alloc_calls++;
    }else if(!strcmp(name, "_dirname")){
        dest = arena+(WRITABLE_BASE-MAC8_BASE)+PathOffset;
        count = a0 ? string_length(plan, arena, stack, a0, PathBytes) : 0;
        if(count<0)
            return -1;
        left = a0 ? guest_read(plan, arena, stack, a0, count+1, 1) : 0;
        if(a0 && !left)
            return -1;
        i = count;
        while(i>1 && left[i-1]=='/')
            i--;
        while(i && left[i-1]!='/')
            i--;
        while(i>1 && left[i-1]=='/')
            i--;
        if(i)
            memmove(dest, left, i);
        else {
            dest[0] = '.';
            i = 1;
        }
        dest[i] = 0;
        *result = WRITABLE_BASE+PathOffset;
    }else if(!strcmp(name, "_pathconf")){
        count = string_length(plan, arena, stack, a0, PathBytes);
        if(count<0)
            return -1;
        left = guest_read(plan, arena, stack, a0, count+1, 1);
        if(!left)
            return -1;
        if(count==1 && (*left=='.' || *left=='/') && (unsigned int)a1==5)
            *result = PathBytes;
        else {
            *result = ~(Word)0;
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, (unsigned int)a1==5 ? 2 : 22);
        }
    }else if(!strcmp(name, "_realpath$DARWIN_EXTSN") || !strcmp(name, "_realpath")){
        count = string_length(plan, arena, stack, a0, PathBytes);
        if(count<0)
            return -1;
        left = guest_read(plan, arena, stack, a0, count+1, 1);
        if(!left)
            return -1;
        if(count!=1 || (*left!='.' && *left!='/')){
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 2);
            return 1;
        }
        if(!a1){
            offset = mac8_alloc(heap, 2);
            if(offset==Mac8HeapBytes){
                write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 12);
                return 1;
            }
            a1 = HEAP_BASE+offset;
            out->alloc_calls++;
        }
        dest = guest_write(plan, arena, stack, a1, 2, 1);
        if(!dest)
            return -1;
        dest[0] = '/';
        dest[1] = 0;
        *result = a1;
    }else if(!strcmp(name, "_pthread_key_create")){
        dest = guest_write(plan, arena, stack, a0, 8, 1);
        if(!dest || (a1 && !mac8_access(plan, a1, 1, Mac8Execute)))
            return -1;
        for(i=0; i<KeyLimit && (thread->allocated&(1U<<i)); i++)
            ;
        if(i==KeyLimit)
            *result = 35; /* EAGAIN */
        else {
            thread->allocated |= 1U<<i;
            thread->values[i] = 0;
            write_le(dest, 8, i);
        }
    }else if(!strcmp(name, "_pthread_getspecific") || !strcmp(name, "_pthread_setspecific") ||
             !strcmp(name, "_pthread_key_delete")){
        if(a0>=KeyLimit || !(thread->allocated&(1U<<(unsigned int)a0)))
            *result = strcmp(name, "_pthread_getspecific") ? 22 : 0;
        else if(!strcmp(name, "_pthread_getspecific"))
            *result = thread->values[a0];
        else if(!strcmp(name, "_pthread_setspecific"))
            thread->values[a0] = a1;
        else
            thread->allocated &= ~(1U<<(unsigned int)a0);
    }else if(!strcmp(name, "_atexit")){
        if(!mac8_access(plan, a0, 1, Mac8Execute) || (plan->cpu==Arm64 && a0%4))
            return -1;
        if(thread->cleanup_count==ExitLimit)
            *result = (unsigned int)-1;
        else
            thread->cleanup[thread->cleanup_count++] = a0;
    }else if(!strcmp(name, "_isatty")){
        i = (unsigned int)a0;
        write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, i<3 && !(thread->closed&(1U<<i)) ? 25 : 9);
    }else if(!strcmp(name, "_getenv")){
        count = string_length(plan, arena, stack, a0, 4096);
        if(count<0)
            return -1;
        if(count==6){
            left = guest_read(plan, arena, stack, a0, 7, 1);
            if(!left)
                return -1;
            if(!memcmp(left, "LC_ALL", 7))
                *result = StackBase+LocaleEnv+7;
        }
    }else if(!strcmp(name, "_memchr")){
        if(a2>Mac8Limit)
            return -1;
        if(a2){
            left = guest_read(plan, arena, stack, a0, a2, 1);
            if(!left)
                return -1;
            right = memchr(left, (unsigned char)a1, a2);
            if(right)
                *result = a0+(right-left);
        }
    }else if(!strcmp(name, "_memcpy") || !strcmp(name, "_memmove") || !strcmp(name, "_memcmp")){
        if(a2>Mac8Limit)
            return -1;
        if(!strcmp(name, "_memcmp")){
            if(!a2)
                return 1;
            left = guest_read(plan, arena, stack, a0, a2, 1);
            right = guest_read(plan, arena, stack, a1, a2, 1);
            if(!left || !right)
                return -1;
            *result = (unsigned int)memcmp(left, right, a2);
        }else{
            if(a2){
                left = guest_read(plan, arena, stack, a1, a2, 1);
                dest = guest_write(plan, arena, stack, a0, a2, 1);
                if(!left || !dest)
                    return -1;
                memmove(dest, left, a2);
            }
            *result = a0;
        }
    }else if(!strcmp(name, "_memset") || !strcmp(name, "_bzero") || !strcmp(name, "___bzero")){
        if(strcmp(name, "_memset")){
            a2 = a1;
            a1 = 0;
        }
        if(a2>Mac8Limit)
            return -1;
        if(a2){
            dest = guest_write(plan, arena, stack, a0, a2, 1);
            if(!dest)
                return -1;
            memset(dest, (unsigned char)a1, a2);
        }
        *result = a0;
    }else if(!strcmp(name, "_strcmp") || !strcmp(name, "_strncmp")){
        Word limit = !strcmp(name, "_strcmp") ? 65536 : a2;
        if(limit>65536)
            return -1;
        for(i=0; i<limit; i++){
            left = guest_read(plan, arena, stack, a0+i, 1, 1);
            right = guest_read(plan, arena, stack, a1+i, 1, 1);
            if(!left || !right)
                return -1;
            if(*left!=*right || !*left){
                *result = (unsigned int)((int)*left-(int)*right);
                return 1;
            }
        }
        return strcmp(name, "_strcmp") ? 1 : -1;
    }else if(!strcmp(name, "_printf")){
        if(thread->closed&2)
            return -1;
        count = format_guest(plan, arena, stack, a0, varargs ? varargs : a1,
                             varargs ? StackArgs : DirectArg, formatted,
                             Mac8OutputLimit-out->stdout_bytes);
        if(count<0)
            return -1;
        memcpy(out->stdout_data+out->stdout_bytes, formatted, count);
        out->stdout_bytes += count;
        *result = count;
    }else if(!strcmp(name, "_vsnprintf")){
        count = format_guest(plan, arena, stack, a2, a3, varargs ? StackArgs : IntelVaList,
                             formatted, Mac8OutputLimit);
        if(count<0)
            return -1;
        if(a1){
            i = a1>(Word)count ? (unsigned int)count : a1-1;
            dest = guest_write(plan, arena, stack, a0, i+1, 1);
            if(!dest)
                return -1;
            memcpy(dest, formatted, i);
            dest[i] = 0;
        }
        *result = count;
    }else if(!strcmp(name, "_fopen$DARWIN_EXTSN") || !strcmp(name, "_fopen")){
        count = string_length(plan, arena, stack, a0, PathBytes);
        i = string_length(plan, arena, stack, a1, 16);
        if(count<0 || i>15)
            return -1;
        left = guest_read(plan, arena, stack, a0, count+1, 1);
        right = guest_read(plan, arena, stack, a1, i+1, 1);
        if(!left || !right)
            return -1;
        if(strcmp((const char *)right, "r") && strcmp((const char *)right, "rb"))
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 13); /* EACCES */
        else if(!thread->input || strcmp((const char *)left, thread->input_name))
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 2);
        else if(thread->input_open)
            write_le(arena+(ERRNO_ADDRESS-MAC8_BASE), 4, 24); /* EMFILE */
        else {
            thread->input_open = 1;
            thread->input_offset = thread->input_eof = 0;
            out->file_opens++;
            *result = INPUT_HANDLE;
        }
    }else if(!strcmp(name, "_fgets")){
        if(a2!=INPUT_HANDLE || !thread->input_open || a1==0 || a1>Mac8Limit)
            return -1;
        if(thread->input_offset==thread->input_bytes){
            thread->input_eof = 1;
            return 1;
        }
        offset = thread->input_offset;
        for(i=0; i<a1-1 && offset+i<thread->input_bytes; i++)
            if(thread->input[offset+i]=='\n'){
                i++;
                break;
            }
        dest = guest_write(plan, arena, stack, a0, i+1, 1);
        if(!dest)
            return -1;
        memcpy(dest, thread->input+offset, i);
        dest[i] = 0;
        thread->input_offset += i;
        if(i<a1-1 && offset+i==thread->input_bytes && i && dest[i-1]!='\n')
            thread->input_eof = 1;
        out->file_reads += i;
        *result = a0;
    }else if(!strcmp(name, "_feof")){
        if(a0!=INPUT_HANDLE || !thread->input_open)
            return -1;
        *result = thread->input_eof;
    }else if(!strcmp(name, "_fwrite")){
        if(a1 && a2>Mac8OutputLimit/a1)
            return -1;
        i = a1*a2;
        if(i){
            left = guest_read(plan, arena, stack, a0, i, 1);
            if(!left || !write_stream(thread, out, a3, left, i))
                return -1;
            *result = a2;
        }
    }else if(!strcmp(name, "_fputc") || !strcmp(name, "_putchar")){
        formatted[0] = a0;
        if(!write_stream(thread, out, !strcmp(name, "_putchar") ? STREAM_HANDLE+16 : a1, formatted, 1))
            return -1;
        *result = formatted[0];
    }else if(!strcmp(name, "_ferror") || !strcmp(name, "_fflush") || !strcmp(name, "_fclose")){
        if(a0==INPUT_HANDLE && thread->input_open){
            if(!strcmp(name, "_fclose"))
                thread->input_open = 0;
            return 1;
        }
        if(a0==0 && !strcmp(name, "_fflush"))
            return 1;
        if(a0<STREAM_HANDLE || a0>STREAM_HANDLE+32 || (a0-STREAM_HANDLE)%16)
            return -1;
        i = 1U<<((a0-STREAM_HANDLE)/16);
        if(thread->closed&i)
            return -1;
        if(!strcmp(name, "_fclose"))
            thread->closed |= i;
    }else if(!strcmp(name, "_exit")){
        out->exit_code = a0&255;
        return 2;
    }else if(!strcmp(name, "_free")){
        if(a0 && (a0<HEAP_BASE || a0-HEAP_BASE>=Mac8HeapBytes ||
                  !mac8_free(heap, a0-HEAP_BASE)))
            return -1;
    }else
        return 0;
    return 1;
}

static int
stop_at_import(const Mac8Image *plan, Mac8Stop *out, Word target, Word a0, Word a1)
{
    Word delta;
    if(target < MAC8_UNRESOLVED)
        return 0;
    delta = target-MAC8_UNRESOLVED;
    if(delta%16 || delta/16 >= plan->imports)
        return 0;
    out->pc = target;
    out->arg0 = a0;
    out->arg1 = a1;
    out->name = plan->names[delta/16];
    return 1;
}

enum { OnceLimit = 16 };
#define ONCE_RETURN 0x19000ULL

typedef struct Once Once;
struct Once {
    Word done[OnceLimit], object, link, sp;
    unsigned int count;
};

/* Single-threaded launch. The initializer runs as guest code. A separate
 * control record prevents recursive use and verifies its return frame. */
static int
once_begin(const Mac8Image *plan, unsigned char *arena, unsigned char *stack,
           Once *once, Word object, Word callback, Word link, Word sp)
{
    unsigned int i;
    if(once->object || once->count==OnceLimit || object%8 ||
       !guest_write(plan, arena, stack, object, 8, 1) ||
       !mac8_access(plan, callback, 1, Mac8Execute))
        return -1;
    for(i=0; i<once->count; i++)
        if(once->done[i]==object)
            return 0;
    once->object = object;
    once->link = link;
    once->sp = sp;
    return 1;
}

static Word
once_end(Once *once, Word sp)
{
    if(!once->object || once->sp!=sp)
        return 0;
    once->done[once->count++] = once->object;
    once->object = 0;
    return once->link;
}

static int
intel_start(const Mac8Image *plan, const unsigned char *image, unsigned char *arena,
            unsigned char *stack, int services, unsigned int argc, unsigned int budget, Mac8Heap *heap, Thread *thread, Mac8Stop *out)
{
    CwMachine machine;
    Once once = {0};
    unsigned int i;
    int handled;
    Word result;
    memset(&machine, 0, sizeof(machine));
    machine.image = arena;
    machine.stack = stack;
    machine.stack_base = StackBase;
    machine.plan.base = MAC8_BASE;
    machine.plan.image_bytes = plan->mapped_bytes;
    machine.plan.count = Mac8Segments-1;
    for(i=1; i<Mac8Segments; i++){
        machine.plan.sections[i-1].rva = plan->segments[i].offset;
        machine.plan.sections[i-1].size = plan->segments[i].bytes;
        machine.plan.sections[i-1].permissions = plan->segments[i].protection;
    }
    if(services){
        machine.plan.image_bytes = ServiceExtent;
        i = machine.plan.count++;
        machine.plan.sections[i].rva = Mac8Limit;
        machine.plan.sections[i].size = Mac8ServiceBytes;
        machine.plan.sections[i].permissions = Mac8Read;
        i = machine.plan.count++;
        machine.plan.sections[i].rva = HEAP_BASE-MAC8_BASE;
        machine.plan.sections[i].size = Mac8HeapBytes+Mac8WritableBytes;
        machine.plan.sections[i].permissions = Mac8Read|Mac8Write;
    }
    machine.x87_control = 0x037f;
    machine.x87_tag = 0xffff;
    machine.mxcsr = 0x1f80;
    machine.ip = MAC8_BASE+plan->entry;
    machine.r[4] = StackBase+StackBytes-8;
    machine.r[7] = argc; /* argc in RDI */
    machine.r[6] = StackBase+Argv;
    machine.r[2] = StackBase+Envp;
    machine.r[1] = StackBase+Envp+16;
    for(out->steps=0; out->steps<budget; out->steps++){
        if(machine.ip==EXIT_RETURN){
            if(!thread->exit_sp || thread->exit_sp!=machine.r[4])
                return 0;
            if(!thread->cleanup_count)
                return 2;
            machine.r[4] -= 8;
            write_le(stack+(machine.r[4]-StackBase), 8, EXIT_RETURN);
            machine.ip = thread->cleanup[--thread->cleanup_count];
            continue;
        }
        if(machine.ip==ONCE_RETURN){
            machine.ip = once_end(&once, machine.r[4]);
            if(!machine.ip)
                return 0;
            machine.r[0] = 0;
            continue;
        }
        if(stop_at_import(plan, out, machine.ip, machine.r[7], machine.r[6])){
            Word sp = machine.r[4], link;
            const char *name = (const char *)image+out->name;
            if(!services)
                return 1;
            if(sp%16!=8 || !stack_span(sp, 8))
                return 0;
            link = read_le(stack+(sp-StackBase), 8);
            out->link = link;
            out->arg2 = machine.r[2];
            out->arg3 = machine.r[1];
            if(!mac8_access(plan, link, 1, Mac8Execute) &&
               !(link==ONCE_RETURN && once.object && once.sp==sp+8) &&
               !(link==EXIT_RETURN && thread->exit_sp==sp+8))
                return 0;
            if(!strcmp(name, "____chkstk_darwin")){
                if(machine.r[0]>sp+8-StackBase)
                    return 0;
                handled = 1;
                result = machine.r[0];
            }else if(!strcmp(name, "_pthread_once")){
                handled = once_begin(plan, arena, stack, &once, out->arg0, out->arg1, link, sp+8);
                if(handled<0)
                    return 0;
                if(handled){
                    write_le(stack+(sp-StackBase), 8, ONCE_RETURN);
                    machine.ip = out->arg1;
                    out->pc = out->name = 0;
                    continue;
                }
                handled = 1;
                result = 0;
            }else
                handled = service_call(plan, arena, stack, heap, name,
                                       out->arg0, out->arg1, machine.r[2], machine.r[1], 0, &result, thread, out);
            if(handled==2 && thread->cleanup_count){
                thread->exit_sp = sp+8;
                write_le(stack+(sp-StackBase), 8, EXIT_RETURN);
                machine.ip = thread->cleanup[--thread->cleanup_count];
                out->pc = out->name = 0;
                continue;
            }
            if(handled!=1)
                return handled<0 ? 0 : handled==0 ? 1 : 2;
            machine.r[4] += 8;
            machine.r[0] = result;
            machine.ip = link;
            out->pc = out->name = 0;
            continue;
        }
        out->last_pc = machine.ip;
        if(cw_cpu_step(&machine) != CW_OK)
            return 0;
    }
    return 0;
}

static Word
arm_shift(Word v, unsigned int mode, unsigned int count, unsigned int width)
{
    if(width==32)
        v = (unsigned int)v;
    if(!count)
        return v;
    if(mode==0)
        return v<<count;
    if(mode==1)
        return v>>count;
    if(mode==2){
        if(width==32)
            v = sign_extend(v, 32);
        return (v>>count) | ((v>>63) ? ~(~(Word)0>>count) : 0);
    }
    return (v>>count)|(v<<(width-count));
}

static unsigned int
arm_flags(Word a, Word b, Word value, int wide, int subtract)
{
    Word mask = wide ? ~(Word)0 : 0xffffffffU;
    Word sign = (mask>>1)+1;
    a &= mask;
    b &= mask;
    value &= mask;
    return ((value&sign)!=0)*8 + (!value)*4 +
           (subtract ? a>=b : value<a)*2 +
           (((a^value)&(subtract ? a^b : ~(a^b))&sign)!=0);
}

static int
arm_cond(unsigned int flags, unsigned int cond)
{
    int n = (flags&8)!=0, z = (flags&4)!=0, c = (flags&2)!=0, v = (flags&1)!=0;
    int yes;
    switch(cond>>1){
    case 0: yes=z; break;
    case 1: yes=c; break;
    case 2: yes=n; break;
    case 3: yes=v; break;
    case 4: yes=c && !z; break;
    case 5: yes=n==v; break;
    case 6: yes=n==v && !z; break;
    default: return 1;
    }
    return yes!=(int)(cond&1);
}

static int
arm_bitmask(unsigned int op, Word *out)
{
    unsigned int tag = ((op>>16)&64) | ((~op>>10)&63);
    unsigned int len = 0, size, ones, rotate, i, width = (op>>31) ? 64 : 32;
    Word elem, mask;
    while(tag>>1){
        len++;
        tag >>= 1;
    }
    size = 1U<<len;
    ones = (op>>10)&(size-1);
    rotate = (op>>16)&(size-1);
    if(!len || size>width || ones==size-1)
        return 0;
    mask = size==64 ? ~(Word)0 : ((Word)1<<size)-1;
    elem = ((Word)1<<(ones+1))-1;
    if(rotate)
        elem = ((elem>>rotate)|(elem<<(size-rotate)))&mask;
    *out = 0;
    for(i=0; i<width; i+=size)
        *out |= elem<<i;
    return 1;
}

static int
arm_start(const Mac8Image *plan, const unsigned char *image, unsigned char *arena,
          unsigned char *stack, int services, unsigned int argc, unsigned int budget, Mac8Heap *heap, Thread *thread, Mac8Stop *out)
{
    Word r[31] = {0}, sp = StackBase+StackBytes, result;
    Once once = {0};
    unsigned char fp[32][16] = {{0}}, vector[16];
    Word pc = MAC8_BASE+plan->entry, next, addr, v, imm;
    unsigned int op, rd, rn, rt2, bytes, mode, cond;
    Word access;
    unsigned int flags = 0;
    int handled, wide, sub;
    const unsigned char *p;
    unsigned char *dst;
    r[0] = argc;
    r[1] = StackBase+Argv;
    r[2] = StackBase+Envp;
    r[3] = StackBase+Envp+16;
    for(out->steps=0; out->steps<budget; out->steps++){
        if(pc==EXIT_RETURN){
            if(!thread->exit_sp || thread->exit_sp!=sp)
                return 0;
            if(!thread->cleanup_count)
                return 2;
            r[30] = EXIT_RETURN;
            pc = thread->cleanup[--thread->cleanup_count];
            continue;
        }
        if(pc==ONCE_RETURN){
            pc = once_end(&once, sp);
            if(!pc)
                return 0;
            r[0] = 0;
            r[30] = pc;
            continue;
        }
        if(stop_at_import(plan, out, pc, r[0], r[1])){
            const char *name = (const char *)image+out->name;
            if(!services)
                return 1;
            out->link = r[30];
            out->arg2 = r[2];
            out->arg3 = r[3];
            if(sp%16 || r[30]%4 ||
               (!mac8_access(plan, r[30], 4, Mac8Execute) &&
                !(r[30]==ONCE_RETURN && once.object && once.sp==sp) &&
                !(r[30]==EXIT_RETURN && thread->exit_sp==sp)))
                return 0;
            if(!strcmp(name, "___chkstk_darwin")){
                if(r[9]>sp-StackBase)
                    return 0;
                handled = 1;
                result = r[0];
            }else if(!strcmp(name, "_pthread_once")){
                if(out->arg1%4)
                    return 0;
                handled = once_begin(plan, arena, stack, &once, out->arg0, out->arg1, r[30], sp);
                if(handled<0)
                    return 0;
                if(handled){
                    r[30] = ONCE_RETURN;
                    pc = out->arg1;
                    out->pc = out->name = 0;
                    continue;
                }
                handled = 1;
                result = 0;
            }else
                handled = service_call(plan, arena, stack, heap, name,
                                       out->arg0, out->arg1, r[2], r[3], sp, &result, thread, out);
            if(handled==2 && thread->cleanup_count){
                thread->exit_sp = sp;
                r[30] = EXIT_RETURN;
                pc = thread->cleanup[--thread->cleanup_count];
                out->pc = out->name = 0;
                continue;
            }
            if(handled!=1)
                return handled<0 ? 0 : handled==0 ? 1 : 2;
            r[0] = result;
            pc = r[30];
            out->pc = out->name = 0;
            continue;
        }
        out->last_pc = pc;
        if(pc%4 || !mac8_access(plan, pc, 4, Mac8Execute))
            return 0;
        op = read_le(arena+(pc-MAC8_BASE), 4);
        next = pc+4;
        rd = op&31;
        rn = (op>>5)&31;
        v = rn==31 ? sp : r[rn];
        imm = (op>>10)&0xfff;
        if((op&0x1f800000U)==0x11000000U){ /* ADD/SUB (immediate) */
            if(op&(1U<<22))
                imm <<= 12;
            wide = op>>31;
            sub = (op>>30)&1;
            addr = sub ? v-imm : v+imm;
            if(!wide)
                addr = (unsigned int)addr;
            if(op&(1U<<29))
                flags = arm_flags(v, imm, addr, wide, sub);
            if(rd!=31)
                r[rd] = addr;
            else if(!(op&(1U<<29))){
                if(addr%16 || !stack_span(addr, 0))
                    return 0;
                sp = addr;
            }
        }else if((op&0x1fe00000U)==0x0b200000U){ /* ADD/SUB (extended register) */
            mode = (op>>13)&7;
            imm = (op>>10)&7;
            wide = op>>31;
            sub = (op>>30)&1;
            rt2 = (op>>16)&31;
            bytes = 8U<<(mode&3);
            if(imm>4 || (!wide && bytes==64))
                return 0;
            access = rt2==31 ? 0 : r[rt2];
            if(bytes<64){
                access &= ((Word)1<<bytes)-1;
                if(mode&4)
                    access = sign_extend(access, bytes);
            }
            access <<= imm;
            addr = sub ? v-access : v+access;
            if(!wide)
                addr = (unsigned int)addr;
            if(op&(1U<<29))
                flags = arm_flags(v, access, addr, wide, sub);
            if(rd!=31)
                r[rd] = addr;
            else if(!(op&(1U<<29))){
                if(addr%16 || !stack_span(addr, 0))
                    return 0;
                sp = addr;
            }
        }else if((op&0x1f200000U)==0x0b000000U){ /* ADD/SUB (shifted register) */
            mode = (op>>22)&3;
            bytes = (op>>10)&63;
            wide = op>>31;
            sub = (op>>30)&1;
            rt2 = (op>>16)&31;
            if(mode==3 || (!wide && bytes>=32))
                return 0;
            access = arm_shift(rt2==31 ? 0 : r[rt2], mode, bytes, wide ? 64 : 32);
            v = rn==31 ? 0 : r[rn];
            addr = sub ? v-access : v+access;
            if(op&(1U<<29))
                flags = arm_flags(v, access, addr, wide, sub);
            if(rd!=31)
                r[rd] = wide ? addr : (unsigned int)addr;
        }else if((op&0x7e000000U)==0x28000000U && (mode=(op>>23)&3)!=0){ /* STP/LDP W/X */
            bytes = (op>>31) ? 8 : 4;
            rt2 = (op>>10)&31;
            addr = v+sign_extend((op>>15)&0x7f, 7)*bytes;
            access = mode==1 ? v : addr;
            if(mode!=2 && rn!=31 && (rn==rd || rn==rt2))
                return 0;
            if(mode!=2 && rn==31 && (addr%16 || !stack_span(addr, 0)))
                return 0;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, access, 2*bytes, services);
                if(!p || rd==rt2)
                    return 0;
                if(rd!=31)
                    r[rd] = read_le(p, bytes);
                if(rt2!=31)
                    r[rt2] = read_le(p+bytes, bytes);
            }else{
                dst = guest_write(plan, arena, stack, access, 2*bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
                write_le(dst+bytes, bytes, rt2==31 ? 0 : r[rt2]);
            }
            if(mode!=2){
                if(rn==31)
                    sp = addr;
                else
                    r[rn] = addr;
            }
        }else if((op&0x3f200000U)==0x38000000U && (mode=(op>>10)&3)!=2){ /* LDUR/STUR or indexed */
            bytes = 1U<<(op>>30);
            addr = v+sign_extend((op>>12)&0x1ff, 9);
            access = mode==1 ? v : addr;
            if(mode && ((rn!=31 && rd==rn) ||
                        (rn==31 && (addr%16 || !stack_span(addr, 0)))))
                return 0;
            cond = (op>>22)&3;
            if(cond){
                p = guest_read(plan, arena, stack, access, bytes, services);
                if(!p)
                    return 0;
                if(cond>1 && (bytes==8 || (bytes==4 && cond==3)))
                    return 0;
                v = read_le(p, bytes);
                if(cond>1)
                    v = sign_extend(v, bytes*8);
                if(rd!=31)
                    r[rd] = cond==3 ? (unsigned int)v : v;
            }else{
                dst = guest_write(plan, arena, stack, access, bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
            }
            if(mode){
                if(rn==31)
                    sp = addr;
                else
                    r[rn] = addr;
            }
        }else if((op&0x1f000000U)==0x0a000000U){ /* Logical, shifted register */
            rt2 = (op>>16)&31;
            bytes = (op>>10)&63;
            wide = op>>31;
            if(!wide && bytes>=32)
                return 0;
            v = rn==31 ? 0 : r[rn];
            access = arm_shift(rt2==31 ? 0 : r[rt2], (op>>22)&3, bytes, wide ? 64 : 32);
            if(op&(1U<<21))
                access = ~access;
            mode = (op>>29)&3;
            if(mode==1)
                v |= access;
            else if(mode==2)
                v ^= access;
            else
                v &= access;
            if(!(op>>31))
                v = (unsigned int)v;
            if(mode==3)
                flags = ((v>>(op>>31 ? 63 : 31))!=0)*8 + (!v)*4;
            if(rd!=31)
                r[rd] = v;
        }else if((op&0x1f000000U)==0x10000000U && rd!=31){ /* ADR/ADRP */
            imm = (((op>>5)&0x7ffff)<<2) | ((op>>29)&3);
            access = sign_extend(imm, 21);
            r[rd] = op>>31 ? (pc&~(Word)4095)+(access<<12) : pc+access;
        }else if((op&0x1f800000U)==0x12800000U){ /* MOVN/MOVZ/MOVK */
            mode = (op>>29)&3;
            bytes = ((op>>21)&3)*16;
            if(mode==1 || (!(op>>31) && bytes>=32))
                return 0;
            v = (Word)((op>>5)&0xffff)<<bytes;
            if(mode==0)
                v = ~v;
            if(mode==3 && rd!=31)
                v |= r[rd]&~((Word)0xffff<<bytes);
            if(rd!=31)
                r[rd] = op>>31 ? v : (unsigned int)v;
        }else if((op&0x3f200c00U)==0x38200800U){ /* LDR/STR, register offset */
            rt2 = (op>>16)&31;
            mode = (op>>13)&7;
            bytes = 1U<<(op>>30);
            access = rt2==31 ? 0 : r[rt2];
            if(mode==2)
                access = (unsigned int)access;
            else if(mode==6)
                access = sign_extend((unsigned int)access, 32);
            else if(mode!=3 && mode!=7)
                return 0;
            if(op&(1U<<12))
                access *= bytes;
            addr = v+access;
            mode = (op>>22)&3;
            if(mode){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                if(mode>1 && (bytes==8 || (bytes==4 && mode==3)))
                    return 0;
                v = read_le(p, bytes);
                if(mode>1)
                    v = sign_extend(v, bytes*8);
                if(rd!=31)
                    r[rd] = mode==3 ? (unsigned int)v : v;
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
            }
        }else if((op&0x7fa00000U)==0x13800000U){ /* EXTR */
            wide = op>>31;
            bytes = wide ? 64 : 32;
            mode = (op>>10)&63;
            rt2 = (op>>16)&31;
            if(mode>=bytes || ((op>>22)&1)!=(unsigned int)wide)
                return 0;
            access = rt2==31 ? 0 : r[rt2];
            if(!wide)
                access = (unsigned int)access;
            v = access;
            if(mode)
                v = (access>>mode)|((rn==31 ? 0 : r[rn])<<(bytes-mode));
            if(rd!=31)
                r[rd] = wide ? v : (unsigned int)v;
        }else if((op&0x1f800000U)==0x13000000U){ /* SBFM/BFM/UBFM */
            unsigned int first = (op>>16)&63, last = (op>>10)&63, shift;
            Word mask;
            wide = op>>31;
            bytes = wide ? 64 : 32;
            mode = (op>>29)&3;
            if(mode==3 || ((op>>22)&1)!=(unsigned int)wide || first>=bytes || last>=bytes)
                return 0;
            v = rn==31 ? 0 : r[rn];
            if(!wide)
                v = (unsigned int)v;
            if(last>=first){
                shift = last-first+1;
                mask = shift==64 ? ~(Word)0 : ((Word)1<<shift)-1;
                v >>= first;
            }else{
                shift = bytes-first;
                mask = (((Word)1<<(last+1))-1)<<shift;
                v <<= shift;
            }
            v &= mask;
            if(mode==0){
                unsigned int top = last>=first ? last-first : bytes-first+last;
                if(v&((Word)1<<top))
                    v |= ~((Word)0) << top;
            }
            if(rd!=31){
                if(mode==1)
                    v |= r[rd]&~mask;
                r[rd] = wide ? v : (unsigned int)v;
            }
        }else if((op&0x3f800000U)==0x39800000U){ /* LDRSB/LDRSH/LDRSW, unsigned offset */
            mode = (op>>22)&1;
            bytes = 1U<<(op>>30);
            if(bytes==8 || (bytes==4 && mode))
                return 0;
            addr = v+imm*bytes;
            p = guest_read(plan, arena, stack, addr, bytes, services);
            if(!p)
                return 0;
            v = sign_extend(read_le(p, bytes), bytes*8);
            if(rd!=31)
                r[rd] = mode ? (unsigned int)v : v;
        }else if((op&0x3f800000U)==0x39000000U){ /* LDR/STR, unsigned offset */
            bytes = 1U<<(op>>30);
            addr = v+imm*bytes;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                if(rd!=31)
                    r[rd] = read_le(p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                write_le(dst, bytes, rd==31 ? 0 : r[rd]);
            }
        }else if((op&0xbffffc00U)==0x0ea00800U){ /* REV64 V.2S/V.4S */
            bytes = (op&(1U<<30)) ? 16 : 8;
            memset(vector, 0, 16);
            for(mode=0; mode<bytes; mode+=4)
                memcpy(vector+mode, fp[rn]+(mode^4), 4);
            memcpy(fp[rd], vector, 16);
        }else if((op&0xfffffc00U)==0x4d408400U){ /* LD1 D lane 1 */
            p = guest_read(plan, arena, stack, v, 8, services);
            if(!p)
                return 0;
            memcpy(fp[rd]+8, p, 8);
        }else if((op&0xffe0fc00U)==0x4e201c00U){ /* AND V.16B */
            rt2 = (op>>16)&31;
            for(bytes=0; bytes<16; bytes++)
                fp[rd][bytes] = fp[rn][bytes]&fp[rt2][bytes];
        }else if((op&0xffe0fc00U)==0x6ee08c00U){ /* CMEQ V.2D */
            rt2 = (op>>16)&31;
            for(bytes=0; bytes<16; bytes+=8)
                memset(fp[rd]+bytes, memcmp(fp[rn]+bytes, fp[rt2]+bytes, 8) ? 0 : 255, 8);
        }else if((op&0xfffffc00U)==0x6e205800U){ /* MVN V.16B */
            for(bytes=0; bytes<16; bytes++)
                fp[rd][bytes] = ~fp[rn][bytes];
        }else if((op&0xffe0fc00U)==0x4e801800U){ /* UZP1 V.4S */
            rt2 = (op>>16)&31;
            memcpy(vector, fp[rn], 4);
            memcpy(vector+4, fp[rn]+8, 4);
            memcpy(vector+8, fp[rt2], 4);
            memcpy(vector+12, fp[rt2]+8, 4);
            memcpy(fp[rd], vector, 16);
        }else if((op&0xdfe0fc00U)==0x4ea08400U){ /* ADD/SUB V.4S */
            rt2 = (op>>16)&31;
            for(bytes=0; bytes<16; bytes+=4){
                v = read_le(fp[rn]+bytes, 4);
                access = read_le(fp[rt2]+bytes, 4);
                write_le(fp[rd]+bytes, 4, (op&(1U<<29)) ? v-access : v+access);
            }
        }else if((op&0xfffffc00U)==0x4eb1b800U){ /* ADDV S, V.4S */
            v = 0;
            for(bytes=0; bytes<16; bytes+=4)
                v += read_le(fp[rn]+bytes, 4);
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 4, v);
        }else if((op&0xfffffc00U)==0x4e080c00U){ /* DUP Vd.2D, Xn */
            v = rn==31 ? 0 : r[rn];
            write_le(fp[rd], 8, v);
            write_le(fp[rd]+8, 8, v);
        }else if((op&0xffffffe0U)==0xd53b4400U){ /* MRS FPCR, reset profile */
            if(rd!=31)
                r[rd] = 0;
        }else if((op&0xfffffc00U)==0x1e614000U){ /* FNEG D */
            v = read_le(fp[rn], 8)^((Word)1<<63);
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xfffffc00U)==0x1e604000U){ /* FMOV D, D */
            v = read_le(fp[rn], 8);
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xffe01fe0U)==0x1e601000U){ /* FMOV D, immediate */
            imm = (op>>13)&255;
            v = ((Word)(imm&128)<<56) | ((Word)((imm&64) ? 0xff : 0x100)<<54) |
                ((Word)(imm&63)<<48);
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0x7ffffc00U)==0x1e780000U){ /* FCVTZS W/X, D */
            wide = op>>31;
            v = mac8_fp_to_int(read_le(fp[rn], 8), wide ? 64 : 32);
            if(rd!=31)
                r[rd] = wide ? v : (unsigned int)v;
        }else if((op&0x7ffefc00U)==0x1e620000U){ /* SCVTF/UCVTF D, W/X */
            v = mac8_fp_from_int(rn==31 ? 0 : r[rn], op>>31 ? 64 : 32, !(op&(1U<<16)));
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xffe00000U)==0x1f400000U){ /* FMADD/FMSUB D */
            rt2 = (op>>16)&31;
            mode = (op>>10)&31;
            access = read_le(fp[rn], 8)^((Word)(op&0x8000U)<<48);
            if(!mac8_fma(access, read_le(fp[rt2], 8), read_le(fp[mode], 8), &v))
                return 0;
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xffe00c00U)==0x1e600c00U){ /* FCSEL D */
            rt2 = (op>>16)&31;
            v = read_le(fp[arm_cond(flags, (op>>12)&15) ? rn : rt2], 8);
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xffe0fc17U)==0x1e602000U){ /* FCMP D */
            rt2 = (op>>16)&31;
            if((op&8) && rt2)
                return 0;
            flags = mac8_fp_compare(read_le(fp[rn], 8), (op&8) ? 0 : read_le(fp[rt2], 8));
        }else if((op&0xffe0ec00U)==0x1e604800U){ /* FMIN/FMAX D */
            rt2 = (op>>16)&31;
            v = read_le(fp[rn], 8);
            access = read_le(fp[rt2], 8);
            cond = mac8_fp_compare(v, access);
            if(cond==3)
                v = (mac8_fp_compare(v, v)==3 ? v : access)|0x0008000000000000ULL;
            else if(cond==6)
                v = (op&(1U<<12)) ? v|access : v&access;
            else if(cond==((op&(1U<<12)) ? 2U : 8U))
                v = access;
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xffe0fc00U)==0x1e602800U ||
                 (op&0xffe0fc00U)==0x1e600800U || (op&0xffe0fc00U)==0x1e603800U ||
                 (op&0xffe0fc00U)==0x1e601800U){ /* Scalar D arithmetic */
            Word left = read_le(fp[rn], 8);
            Word right = read_le(fp[(op>>16)&31], 8);
            mode = op&0xfc00U;
            if(mode==0x1800U){
                if(!mac8_fp_div(left, right, &v))
                    return 0;
            }else if(mode==0x800U){
                if(!mac8_fma(left, right, (left^right)&(1ULL<<63), &v))
                    return 0;
            }else{
                right ^= (Word)(op&0x1000U)<<51;
                if(!mac8_fma(left, 0x3ff0000000000000ULL, right, &v))
                    return 0;
            }
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, v);
        }else if((op&0xfffffc00U)==0x9e670000U){ /* FMOV D, X */
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 8, rn==31 ? 0 : r[rn]);
        }else if((op&0xfffffc00U)==0x9e660000U){ /* FMOV X, D */
            if(rd!=31)
                r[rd] = read_le(fp[rn], 8);
        }else if((op&0xfffffc00U)==0x1e260000U){ /* FMOV W, S */
            if(rd!=31)
                r[rd] = read_le(fp[rn], 4);
        }else if((op&0xbffffc00U)==0x0e205800U){ /* CNT V.8B/V.16B */
            unsigned int k, value;
            bytes = (op&(1U<<30)) ? 16 : 8;
            for(k=0; k<bytes; k++){
                mode = 0;
                for(value=fp[rn][k]; value; value &= value-1)
                    mode++;
                fp[rd][k] = mode;
            }
            if(bytes==8)
                memset(fp[rd]+8, 0, 8);
        }else if((op&0xbffffc00U)==0x2e303800U){ /* UADDLV H, V.8B/V.16B */
            v = 0;
            bytes = (op&(1U<<30)) ? 16 : 8;
            for(mode=0; mode<bytes; mode++)
                v += fp[rn][mode];
            memset(fp[rd], 0, 16);
            write_le(fp[rd], 2, v);
        }else if((op&0x9ff8fc00U)==0x0f00e400U){ /* MOVI, byte or byte-mask immediate */
            imm = (((op>>16)&7)<<5) | ((op>>5)&31);
            if(op&(1U<<29)){
                for(bytes=0; bytes<8; bytes++)
                    fp[rd][bytes] = fp[rd][bytes+8] = (imm&(1U<<bytes)) ? 255 : 0;
                if(!(op&(1U<<30)))
                    memset(fp[rd]+8, 0, 8);
            }else{
                memset(fp[rd], imm, 8);
                memset(fp[rd]+8, (op&(1U<<30)) ? imm : 0, 8);
            }
        }else if(((op&0xfe000000U)==0xac000000U || (op&0xfe000000U)==0x6c000000U) && (mode=(op>>23)&3)!=0){ /* STP/LDP D/Q */
            bytes = op>>31 ? 16 : 8;
            rt2 = (op>>10)&31;
            addr = v+sign_extend((op>>15)&0x7f, 7)*bytes;
            access = mode==1 ? v : addr;
            if(mode!=2 && rn==31 && (addr%16 || !stack_span(addr, 0)))
                return 0;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, access, 2*bytes, services);
                if(!p || rd==rt2)
                    return 0;
                memset(fp[rd], 0, 16);
                memcpy(fp[rd], p, bytes);
                memset(fp[rt2], 0, 16);
                memcpy(fp[rt2], p+bytes, bytes);
            }else{
                dst = guest_write(plan, arena, stack, access, 2*bytes, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], bytes);
                memcpy(dst+bytes, fp[rt2], bytes);
            }
            if(mode!=2){
                if(rn==31)
                    sp = addr;
                else
                    r[rn] = addr;
            }
        }else if(((op&0xffa00000U)==0x3c800000U || (op&0xffa00000U)==0xfc000000U) &&
                 (mode=(op>>10)&3)!=2){ /* D/Q unscaled/indexed */
            bytes = op>>31 ? 8 : 16;
            addr = v+sign_extend((op>>12)&0x1ff, 9);
            access = mode==1 ? v : addr;
            if(mode && rn==31 && (addr%16 || !stack_span(addr, 0)))
                return 0;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, access, bytes, services);
                if(!p)
                    return 0;
                memset(fp[rd], 0, 16);
                memcpy(fp[rd], p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, access, bytes, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], bytes);
            }
            if(mode){
                if(rn==31)
                    sp = addr;
                else
                    r[rn] = addr;
            }
        }else if((op&0xffa00c00U)==0x3ca00800U ||
                 (op&0xffa00c00U)==0xfc200800U){ /* LDR/STR D/Q, register offset */
            bytes = op>>31 ? 8 : 16;
            rt2 = (op>>16)&31;
            mode = (op>>13)&7;
            access = rt2==31 ? 0 : r[rt2];
            if(mode==2)
                access = (unsigned int)access;
            else if(mode==6)
                access = sign_extend((unsigned int)access, 32);
            else if(mode!=3 && mode!=7)
                return 0;
            addr = v+((op&(1U<<12)) ? access*bytes : access);
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                memset(fp[rd], 0, 16);
                memcpy(fp[rd], p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], bytes);
            }
        }else if((op&0xff800000U)==0xfd000000U ||
                 (op&0xff800000U)==0x3d800000U){ /* LDR/STR D/Q, unsigned offset */
            bytes = (op>>31) ? 8 : 16;
            addr = v+imm*bytes;
            if(op&(1U<<22)){
                p = guest_read(plan, arena, stack, addr, bytes, services);
                if(!p)
                    return 0;
                memset(fp[rd], 0, 16);
                memcpy(fp[rd], p, bytes);
            }else{
                dst = guest_write(plan, arena, stack, addr, bytes, services);
                if(!dst)
                    return 0;
                memcpy(dst, fp[rd], bytes);
            }
        }else if((op&0x1f800000U)==0x12000000U){ /* AND/ORR/EOR/ANDS, immediate */
            if(!arm_bitmask(op, &access))
                return 0;
            v = rn==31 ? 0 : r[rn];
            mode = (op>>29)&3;
            if(mode==1)
                v |= access;
            else if(mode==2)
                v ^= access;
            else
                v &= access;
            if(!(op>>31))
                v = (unsigned int)v;
            if(mode==3)
                flags = ((v>>(op>>31 ? 63 : 31))!=0)*8 + (!v)*4;
            if(rd!=31)
                r[rd] = v;
            else if(mode!=3)
                return 0;
        }else if((op&0x3fe00410U)==0x3a400000U){ /* CCMP/CCMN */
            if(arm_cond(flags, (op>>12)&15)){
                rt2 = (op>>16)&31;
                v = rn==31 ? 0 : r[rn];
                access = (op&(1U<<11)) ? rt2 : rt2==31 ? 0 : r[rt2];
                sub = (op>>30)&1;
                flags = arm_flags(v, access, sub ? v-access : v+access, op>>31, sub);
            }else
                flags = op&15;
        }else if((op&0x7fe0f800U)==0x1ac00800U){ /* UDIV/SDIV */
            wide = op>>31;
            bytes = wide ? 64 : 32;
            rt2 = (op>>16)&31;
            v = rn==31 ? 0 : r[rn];
            access = rt2==31 ? 0 : r[rt2];
            if(!wide){
                v = (unsigned int)v;
                access = (unsigned int)access;
            }
            if(!access)
                v = 0;
            else if(op&(1U<<10)){
                Word minimum = (Word)1<<(bytes-1);
                Word mask = wide ? ~(Word)0 : 0xffffffffU;
                if(v!=minimum || access!=mask)
                    v = (Word)((int64_t)sign_extend(v, bytes)/(int64_t)sign_extend(access, bytes));
            }else
                v /= access;
            if(rd!=31)
                r[rd] = wide ? v : (unsigned int)v;
        }else if((op&0x7fe0f000U)==0x1ac02000U){ /* Variable shifts */
            wide = op>>31;
            bytes = wide ? 64 : 32;
            rt2 = (op>>16)&31;
            mode = rt2==31 ? 0 : r[rt2]&(bytes-1);
            v = arm_shift(rn==31 ? 0 : r[rn], (op>>10)&3, mode, bytes);
            if(rd!=31)
                r[rd] = wide ? v : (unsigned int)v;
        }else if((op&0x3fe00800U)==0x1a800000U){ /* CSEL/CSINC */
            rt2 = (op>>16)&31;
            if(arm_cond(flags, (op>>12)&15))
                v = rn==31 ? 0 : r[rn];
            else
                v = (rt2==31 ? 0 : r[rt2])+((op>>10)&1);
            if(rd!=31)
                r[rd] = op>>31 ? v : (unsigned int)v;
        }else if((op&0xff000010U)==0x54000000U){ /* B.cond */
            cond = op&15;
            if(arm_cond(flags, cond))
                next = pc+(sign_extend((op>>5)&0x7ffff, 19)<<2);
        }else if((op&0xff600000U)==0x9b200000U){ /* SMADDL/UMADDL and subtract forms */
            rt2 = (op>>16)&31;
            mode = (op>>10)&31;
            v = rn==31 ? 0 : (unsigned int)r[rn];
            access = rt2==31 ? 0 : (unsigned int)r[rt2];
            if(!(op&(1U<<23))){
                v = sign_extend(v, 32);
                access = sign_extend(access, 32);
            }
            v *= access;
            access = mode==31 ? 0 : r[mode];
            if(rd!=31)
                r[rd] = (op&(1U<<15)) ? access-v : access+v;
        }else if((op&0x7fe00000U)==0x1b000000U){ /* MADD/MSUB */
            rt2 = (op>>16)&31;
            mode = (op>>10)&31;
            v = (rn==31 ? 0 : r[rn])*(rt2==31 ? 0 : r[rt2]);
            access = mode==31 ? 0 : r[mode];
            v = (op&(1U<<15)) ? access-v : access+v;
            if(rd!=31)
                r[rd] = op>>31 ? v : (unsigned int)v;
        }else if((op&0x7e000000U)==0x36000000U){ /* TBZ/TBNZ */
            v = rd==31 ? 0 : r[rd];
            mode = ((op>>26)&32) | ((op>>19)&31);
            if(((v>>mode)&1)==((op>>24)&1))
                next = pc+(sign_extend((op>>5)&0x3fff, 14)<<2);
        }else if((op&0x7e000000U)==0x34000000U){ /* CBZ/CBNZ */
            v = rd==31 ? 0 : r[rd];
            if(!(op>>31))
                v = (unsigned int)v;
            if((v!=0)==((op>>24)&1))
                next = pc+(sign_extend((op>>5)&0x7ffff, 19)<<2);
        }else if((op&0x7c000000U)==0x14000000U){ /* B/BL */
            if(op>>31)
                r[30] = next;
            next = pc+(sign_extend(op&0x03ffffffU, 26)<<2);
        }else if(((op&0xfffffc1fU)==0xd61f0000U || (op&0xfffffc1fU)==0xd65f0000U ||
                 (op&0xfffffc1fU)==0xd63f0000U) && rn!=31){ /* BR/BLR/RET */
            next = r[rn];
            if((op&0xfffffc1fU)==0xd63f0000U)
                r[30] = pc+4;
        }else
            return 0;
        pc = next;
    }
    return 0;
}

int
mac9_grant_name(const char *name)
{
    unsigned int i;
    unsigned char c;
    if(!name || !name[0])
        return 0;
    for(i=0; i<64; i++){
        c = name[i];
        if(!c)
            return strcmp(name, ".") && strcmp(name, "..");
        if(!((c>='A' && c<='Z') || (c>='a' && c<='z') ||
             (c>='0' && c<='9') || c=='.' || c=='_' || c=='-'))
            return 0;
    }
    return 0;
}

int
mac9_run(const unsigned char *image, unsigned int length, unsigned char *arena,
         unsigned int capacity, Word guard, unsigned int argc, const char *const *argv,
         unsigned int budget, const char *input_name, const unsigned char *input,
         unsigned int input_bytes, Mac8Stop *out)
{
    Mac8Image plan;
    unsigned char *stack;
    unsigned int image_capacity, i, start = Args, size;
    Mac8Heap *heap;
    Thread thread = {0};
    int status = 0;
    if(!out || !arena || capacity<StackBytes || !argc || argc>(Envp-Argv)/8-1 ||
       !argv || !budget || budget>Mac8MaxBudget || input_bytes>Mac8Limit ||
       (input ? !mac9_grant_name(input_name) : input_name || input_bytes))
        return 0;
    image_capacity = capacity-StackBytes;
    if(guard && image_capacity<ServiceExtent)
        return 0;
    if(!mac8_load_bound(image, length, arena, image_capacity, &plan, guard ? resolve_data : 0))
        return 0;
    if(guard){
        memset(arena+Mac8Limit, 0, ServiceExtent-Mac8Limit);
        arena[Mac8Limit] = 'C';
        rune_locale(arena+Mac8Limit+RuneOffset);
        write_le(arena+Mac8Limit+GuardOffset, 8, guard);
        for(i=0; i<3; i++)
            write_le(arena+Mac8Limit+StreamsOffset+8*i, 8, STREAM_HANDLE+16*i);
    }
    stack = arena+(guard ? ServiceExtent : plan.mapped_bytes);
    memset(stack, 0, StackBytes);
    write_le(stack+Envp, 8, StackBase+LocaleEnv);
    memcpy(stack+LocaleEnv, "LC_ALL=C", sizeof("LC_ALL=C"));
    for(i=0; i<argc; i++){
        if(!argv[i] || strlen(argv[i])>=ArgLimit-start)
            return 0;
        size = strlen(argv[i])+1;
        write_le(stack+Argv+8*i, 8, StackBase+start);
        memcpy(stack+start, argv[i], size);
        start += size;
    }
    memset(out, 0, sizeof(*out));
    heap = malloc(sizeof(*heap));
    if(!heap)
        return 0;
    heap->count = 0;
    thread.input = input;
    thread.input_name = input_name;
    thread.input_bytes = input_bytes;
    if(plan.cpu==Intel64)
        status = intel_start(&plan, image, arena, stack, guard!=0, argc, budget, heap, &thread, out);
    else if(plan.cpu==Arm64)
        status = arm_start(&plan, image, arena, stack, guard!=0, argc, budget, heap, &thread, out);
    free(heap);
    return status;
}


int
mac8_run(const unsigned char *image, unsigned int length, unsigned char *arena,
         unsigned int capacity, Word guard, unsigned int argc, const char *const *argv,
         unsigned int budget, const unsigned char *input, unsigned int input_bytes, Mac8Stop *out)
{
    return mac9_run(image, length, arena, capacity, guard, argc, argv, budget,
                    input ? "input.json" : 0, input, input_bytes, out);
}

int
mac8_start(const unsigned char *image, unsigned int length, unsigned char *arena,
           unsigned int capacity, Word guard, Mac8Stop *out)
{
    static const char *argv[] = {"jq", "--version"};
    return mac8_run(image, length, arena, capacity, guard, 2, argv, StartBudget, 0, 0, out);
}
