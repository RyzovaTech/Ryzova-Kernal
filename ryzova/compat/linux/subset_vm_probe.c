/* SPDX-License-Identifier: AGPL-3.0-only */
/* Host proof harness: real ELF instructions interpreted; NEVER native executed. */
#include "subset_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LIMIT (1U * 1024U * 1024U)
static int64_t output(void *ctx,int fd,const unsigned char *bytes,size_t size)
{
    FILE *stream=fd==2?stderr:stdout;
    (void)ctx;
    if (fwrite(bytes,1,size,stream)!=size)
        return -1;
    return (int64_t)size;
}
int main(int argc,char **argv)
{
    FILE *in;
    long bytes;
    unsigned char *elf, *memory;
    RyzVmResult result;
    int status;
    if (argc!=2) {
        fprintf(stderr,"usage: subset-vm static-linux-elf\n");
        return 64;
    }
    in=fopen(argv[1],"rb");
    if (in==NULL || fseek(in,0,SEEK_END)!=0)
        return 65;
    bytes=ftell(in);
    if (bytes<1 || bytes>LIMIT || fseek(in,0,SEEK_SET)!=0) {
        fclose(in);return 65;
    }
    elf=(unsigned char *)malloc((size_t)bytes);
    memory=(unsigned char *)calloc(1,RYZ_VM_MAX_SPAN);
    if (elf==NULL || memory==NULL ||
        fread(elf,1,(size_t)bytes,in)!=(size_t)bytes) {
        fclose(in);free(elf);free(memory);return 65;
    }
    fclose(in);
    status=ryz_vm_run_static_elf(elf,(size_t)bytes,memory,RYZ_VM_MAX_SPAN,
                                 output,NULL,&result);
    fprintf(stderr,"RYZOVA_PHASE5_VM status=%d exited=%d exit_code=%u steps=%u syscalls=%u\n",
            status,result.exited,(unsigned)result.exit_status,
            (unsigned)result.executed_steps,(unsigned)result.syscall_count);
    free(memory);free(elf);
    return status==RYZ_VM_OK && result.exited && result.exit_status==0?0:2;
}
