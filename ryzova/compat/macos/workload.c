/* SPDX-License-Identifier: GPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#else
#include <string.h>
#endif
#include "dynamic.h"
#include "grant.h"
#include "workload.h"

enum { ArgZero = 512, ArgName = 576, EnvNote = 640, Handle = 3, MaxTransfer = 256 };

static void
pointer(unsigned char *dst, unsigned long long addr)
{
    unsigned int i;
    for(i=0; i<8; i++)
        dst[i] = addr>>(8*i);
}

int
mac_work_args(MacFiles *f, unsigned char *stack)
{
    unsigned int i;

    if(strlen(f->name)>63 || strlen(f->note)!=4)
        return 0;
    for(i=0; i<4; i++)
        if(f->note[i]<' ' || f->note[i]>'~')
            return 0;
    strcpy((char *)stack+ArgZero, "m6");
    strcpy((char *)stack+ArgName, f->name);
    strcpy((char *)stack+EnvNote, "FLEX_NOTE=");
    memmove(stack+EnvNote+10, f->note, 4);
    pointer(stack+WorkArgv, WorkStack+ArgZero);
    pointer(stack+WorkArgv+8, WorkStack+ArgName);
    pointer(stack+WorkEnvp, WorkStack+EnvNote);
    return 1;
}

static unsigned char *
stack_bytes(unsigned char *stack, unsigned long long addr, unsigned long long n)
{
    if(addr<WorkStack || addr-WorkStack>WorkPage || n>WorkPage-(addr-WorkStack))
        return 0;
    return stack+(addr-WorkStack);
}

long
mac_work_call(MacFiles *f, unsigned int id, unsigned long long a,
              unsigned long long b, unsigned long long c, unsigned char *stack)
{
    unsigned char *bytes;
    long result = -1;

    switch(id){
    case MacOpen:
        bytes = stack_bytes(stack, a, 64);
        if(f->fd<0 && b==2 && bytes && memchr(bytes, 0, 64)){
            f->fd = mac_grant_open((char *)bytes);
            if(f->fd>=0){
                f->offset = 0;
                f->opens++;
                result = Handle;
            }
        }
        break;
    case MacRead:
        bytes = stack_bytes(stack, b, c);
        if(a==Handle && f->fd>=0 && c<=MaxTransfer &&
           b>=WorkStack+WorkPage-MaxTransfer && bytes){
            result = mac_grant_read(f->fd, bytes, c, f->offset);
            if(result>=0){
                f->offset += result;
                f->reads++;
            }
        }
        break;
    case MacWrite:
        bytes = stack_bytes(stack, b, c);
        if(!bytes || c>MaxTransfer)
            break;
        if(a==1 && c<=sizeof(f->output)-f->size){
            memmove(f->output+f->size, bytes, c);
            f->size += c;
            f->stdout_calls++;
            result = c;
        }else if(a==Handle && f->fd>=0){
            result = mac_grant_write(f->fd, bytes, c, f->offset);
            if(result>=0){
                f->offset += result;
                f->writes++;
            }
        }
        break;
    case MacClose:
        if(a==Handle && f->fd>=0){
            mac_work_finish(f);
            f->closes++;
            result = 0;
        }
        break;
    }
    if(result<0)
        f->denied++;
    return result;
}

void
mac_work_finish(MacFiles *f)
{
    if(f->fd>=0){
        mac_grant_close(f->fd);
        f->fd = -1;
    }
}
