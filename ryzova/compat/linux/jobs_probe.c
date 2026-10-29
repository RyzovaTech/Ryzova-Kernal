/* SPDX-License-Identifier: AGPL-3.0-only */
/* Linux-host differential test harness, not native-kernel evidence. */
#include "jobs.h"
#include <stdio.h>
#include <stdlib.h>
static int64_t sink(void *context,int fd,const unsigned char *bytes,size_t size)
{
    (void)context;return fwrite(bytes,1,size,fd==2?stderr:stdout)==size?(int64_t)size:-1;
}
static int64_t entropy(void *context,unsigned char *bytes,size_t size)
{
    FILE *file;size_t n;(void)context;
    file=fopen("/dev/urandom","rb");if(!file)return -1;
    n=fread(bytes,1,size,file);fclose(file);return n==size?(int64_t)n:-1;
}
int main(int argc,char **argv)
{
    RyzProcessArgs args;RyzJobConfig config;RyzLinuxFiles files;RyzVmResult result;
    char *texts[RYZ_PROCESS_ARGS],*eq;RyzLinuxExec grants[RYZ_PROCESS_ARGS];size_t gi;
    const char *env[]={"FLEX_MODE=test","PATH=/bin"};
    unsigned char *image,*arena,*input=NULL,*out=NULL;FILE *file;long n;int first=1,status;
    memset(&files,0,sizeof(files));memset(&config,0,sizeof(config));config.random=entropy;
    while(first<argc){
        if(strcmp(argv[first],"-b")==0 && first+1<argc){
            char *end;unsigned long n=strtoul(argv[first+1],&end,10);if(!n || n>16777216 || *end)return 64;config.max_steps=(uint32_t)n;first+=2;
        }else if(strcmp(argv[first],"-x")==0 && first+1<argc && config.exec_count<RYZ_PROCESS_ARGS){texts[config.exec_count++]=argv[first+1];first+=2;}
        else if(strcmp(argv[first],"-i")==0 && first+1<argc && !input){
            file=fopen(argv[first+1],"rb");if(!file)return 65;
            input=malloc(RYZ_LINUX_FILE_MAX+1);out=malloc(RYZ_LINUX_FILE_MAX);if(!input || !out)return 65;
            files.input_size=fread(input,1,RYZ_LINUX_FILE_MAX+1,file);
            if(ferror(file) || files.input_size>RYZ_LINUX_FILE_MAX)return 65;
            fclose(file);files.input=input;files.output=out;files.output_capacity=RYZ_LINUX_FILE_MAX;first+=2;
        }else break;
    }
    if(first>=argc)return 64;
    config.execs=grants;file=fopen(argv[first],"rb");if(!file || fseek(file,0,SEEK_END))return 65;
    n=ftell(file);if(n<=0 || n>RYZ_PROCESS_IMAGE_MAX || fseek(file,0,SEEK_SET))return 65;
    image=malloc((size_t)n);arena=malloc(RYZ_PROCESS_MAX_SPAN);if(!image || !arena)return 65;
    if(fread(image,1,(size_t)n,file)!=(size_t)n)return 65;
    fclose(file);args.argv=(const char *const *)(argv+first);args.argc=(size_t)(argc-first);args.envp=env;args.envc=2;
    for(gi=0;gi<config.exec_count;gi++){
        grants[gi].path=texts[gi];eq=strchr(texts[gi],'=');
        if(eq){
            unsigned char *bytes;long length;
            *eq=0;file=fopen(eq+1,"rb");if(!file || fseek(file,0,SEEK_END))return 65;
            length=ftell(file);if(length<=0 || length>RYZ_PROCESS_IMAGE_MAX || fseek(file,0,SEEK_SET))return 65;
            bytes=malloc((size_t)length);if(!bytes || fread(bytes,1,(size_t)length,file)!=(size_t)length)return 65;
            fclose(file);grants[gi].image=bytes;grants[gi].size=(size_t)length;
        }else{grants[gi].image=image;grants[gi].size=(size_t)n;}
    }
    status=ryz_vm_run_jobs_elf(image,(size_t)n,arena,RYZ_PROCESS_MAX_SPAN,input?&files:NULL,&args,&config,sink,NULL,&result);
    fprintf(stderr,"COMPACT_JOBS_RESULT status=%d exited=%d exit=%u steps=%u syscalls=%u forks=%u execs=%u peak=%u blocked=%u pipebytes=%llu rip=%llx\n",status,result.exited,(unsigned)result.exit_status,(unsigned)result.executed_steps,(unsigned)result.syscall_count,(unsigned)result.forks,(unsigned)result.execs,(unsigned)result.peak_tasks,(unsigned)result.blocked_syscalls,(unsigned long long)result.pipe_bytes,(unsigned long long)result.last_rip);
    if(status==RYZ_VM_OK && result.exited && result.exit_status==0 && files.output_size)fwrite(out,1,files.output_size,stdout);
    for(gi=0;gi<config.exec_count;gi++)if(grants[gi].image!=image)free((void *)grants[gi].image);
    free(image);free(arena);free(input);free(out);return status==RYZ_VM_OK && result.exited && result.exit_status==0?0:2;
}
