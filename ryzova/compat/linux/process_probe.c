/* SPDX-License-Identifier: AGPL-3.0-only */
/* Host reference harness; not a native execution claim. */
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
static int64_t sink(void *context,int fd,const unsigned char *bytes,size_t size)
{
    (void)context;
    return fwrite(bytes,1,size,fd==2?stderr:stdout)==size?(int64_t)size:-1;
}
int main(int argc,char **argv)
{
    FILE *in;
    unsigned char *image,*memory,*input=NULL,*fileout=NULL;
    RyzLinuxFiles files;
    int first=1;
    long size;
    int status;
    const char *env[]={"FLEX_MODE=test"};
    RyzProcessArgs args;
    RyzVmResult result;
    memset(&files,0,sizeof files);
    if(argc>3 && strcmp(argv[1],"-i")==0){
        in=fopen(argv[2],"rb");
        if(in==NULL)return 65;
        input=malloc(RYZ_LINUX_FILE_MAX+1);fileout=malloc(RYZ_LINUX_FILE_MAX);
        if(!input || !fileout)return 65;
        files.input_size=fread(input,1,RYZ_LINUX_FILE_MAX+1,in);
        if(ferror(in) || files.input_size>RYZ_LINUX_FILE_MAX){fclose(in);return 65;}
        fclose(in);files.input=input;files.output=fileout;files.output_capacity=RYZ_LINUX_FILE_MAX;first=3;
    }
    if(argc<=first)return 64;
    in=fopen(argv[first],"rb");
    if(in==NULL || fseek(in,0,SEEK_END)!=0)return 65;
    size=ftell(in);
    if(size<=0 || size>RYZ_PROCESS_IMAGE_MAX || fseek(in,0,SEEK_SET)!=0){fclose(in);return 65;}
    image=malloc((size_t)size); memory=malloc(RYZ_PROCESS_MAX_SPAN);
    if(image==NULL || memory==NULL)return 65;
    if(fread(image,1,(size_t)size,in)!=(size_t)size){fclose(in);return 65;}
    fclose(in);
    args.argv=(const char *const *)(argv+first);args.argc=(size_t)argc-first;
    args.envp=env;args.envc=1;
    status=ryz_vm_run_process_elf(image,(size_t)size,memory,RYZ_PROCESS_MAX_SPAN,input?&files:NULL,&args,sink,NULL,&result);
    fprintf(stderr,"COMPACT_PROCESS_RESULT status=%d exited=%d exit=%u steps=%u syscalls=%u rip=%llx\n",
        status,result.exited,(unsigned)result.exit_status,(unsigned)result.executed_steps,
        (unsigned)result.syscall_count,(unsigned long long)result.last_rip);
    if(status==RYZ_VM_OK && result.exited && result.exit_status==0 && files.output_size)
        fwrite(fileout,1,files.output_size,stdout);
    free(input);free(fileout);free(image);free(memory);
    return status==RYZ_VM_OK && result.exited && result.exit_status==0?0:2;
}
