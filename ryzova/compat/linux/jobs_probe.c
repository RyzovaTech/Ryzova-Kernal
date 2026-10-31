/* SPDX-License-Identifier: AGPL-3.0-only */
/* Linux-host differential test harness, not native-kernel evidence. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "jobs.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "network_posix.h"
#include "resource_posix.h"
#include "resource_cli.h"
static int64_t sink(void *context,int fd,const unsigned char *bytes,size_t size)
{
    ssize_t n;(void)context;n=write(fd==2?2:1,bytes,size);return n<0?-1:(int64_t)n;
}
static int64_t entropy(void *context,unsigned char *bytes,size_t size)
{
    FILE *file;size_t n;(void)context;
    file=fopen("/dev/urandom","rb");if(!file)return -1;
    n=fread(bytes,1,size,file);fclose(file);return n==size?(int64_t)n:-1;
}
int main(int argc,char **argv)
{
    ResourceCLI resources;
    RyzFilesystemResources fs;char *stateinpath=NULL,*stateoutpath=NULL;unsigned char *statein=NULL,*stateout=NULL;
    RyzNetworkResources network;RyzNetworkGrant network_grants[RYZ_NETWORK_GRANTS];NetworkHost network_hosts[RYZ_NETWORK_GRANTS];
    RyzProcessArgs args;RyzJobConfig config;RyzLinuxFiles files;RyzVmResult result;
    char *texts[RYZ_PROCESS_ARGS],*eq;RyzLinuxExec grants[RYZ_PROCESS_ARGS];size_t gi;
    const char *env[]={"FLEX_MODE=test","PATH=/bin"};
    unsigned char *image,*arena,*input=NULL,*out=NULL;FILE *file;long n;size_t total_image_bytes;int first=1,status;
    memset(&network,0,sizeof network);memset(network_grants,0,sizeof network_grants);network.grants=network_grants;network.now_ns=network_now;network.wait=network_wait;
    memset(&resources,0,sizeof resources);
    umask(077);memset(&fs,0,sizeof fs);
    memset(&files,0,sizeof(files));memset(&config,0,sizeof(config));config.random=entropy;
    while(first<argc){
        if(strcmp(argv[first],"-M")==0 && first+1<argc && resources.resources.count<RYZ_FS_MOUNTS){resources.mounts_text[resources.resources.count++]=argv[first+1];first+=2;}
        else if(strcmp(argv[first],"-A")==0 && first+1<argc && resources.resources.view_count<16){resources.views_text[resources.resources.view_count++]=argv[first+1];first+=2;}
        else if(strcmp(argv[first],"-K")==0 && first+1<argc && !resources.control){resources.control=argv[first+1];first+=2;}
        else if(strcmp(argv[first],"-r")==0){config.root_tree=1;first++;}
        else if(strcmp(argv[first],"-B")==0 && first+1<argc){char *end;unsigned long n=strtoul(argv[first+1],&end,10);if(!n || n>150994944 || *end)return 64;config.arena_bytes_max=n;first+=2;}
        else if(strcmp(argv[first],"-b")==0 && first+1<argc){
            char *end;unsigned long n=strtoul(argv[first+1],&end,10);if(!n || n>16777216 || *end)return 64;config.max_steps=(uint32_t)n;first+=2;
        }else if(strcmp(argv[first],"-n")==0 && first+1<argc && network.count<RYZ_NETWORK_GRANTS){
            if(!network_parse(argv[first+1],&network_grants[network.count],&network_hosts[network.count]))return 64;
            network.count++;first+=2;
        }else if(strcmp(argv[first],"-t")==0 && first+1<argc){char *end;unsigned long value=strtoul(argv[first+1],&end,10);if(*end || !value || value>10000)return 64;network.wall_milliseconds=(unsigned int)value;first+=2;
        }else if(strcmp(argv[first],"-R")==0 && first+1<argc && !stateinpath){stateinpath=argv[first+1];first+=2;
        }else if(strcmp(argv[first],"-W")==0 && first+1<argc && !stateoutpath){stateoutpath=argv[first+1];first+=2;
        }else if(strcmp(argv[first],"-x")==0 && first+1<argc && config.exec_count<RYZ_PROCESS_ARGS){texts[config.exec_count++]=argv[first+1];first+=2;}
        else if(strcmp(argv[first],"-i")==0 && first+1<argc && !input){
            file=fopen(argv[first+1],"rb");if(!file)return 65;
            input=malloc(RYZ_LINUX_FILE_MAX+1);out=malloc(RYZ_LINUX_FILE_MAX);if(!input || !out)return 65;
            files.input_size=fread(input,1,RYZ_LINUX_FILE_MAX+1,file);
            if(ferror(file) || files.input_size>RYZ_LINUX_FILE_MAX)return 65;
            fclose(file);files.input=input;files.output=out;files.output_capacity=RYZ_LINUX_FILE_MAX;first+=2;
        }else break;
    }
    if(first>=argc || (network.wall_milliseconds && !network.count))return 64;
    if(network.count)config.network=&network;
    if(stateinpath || stateoutpath)config.filesystem=&fs;
    if(stateinpath){
        file=fopen(stateinpath,"rb");if(!file || fseek(file,0,SEEK_END))return 65;
        n=ftell(file);if(n<=0 || n>RYZ_FS_SNAPSHOT_MAX || fseek(file,0,SEEK_SET))return 65;
        statein=malloc((size_t)n);if(!statein || fread(statein,1,(size_t)n,file)!=(size_t)n)return 65;
        fclose(file);fs.input=statein;fs.input_size=(size_t)n;
    }
    if(stateoutpath){stateout=malloc(RYZ_FS_SNAPSHOT_MAX);if(!stateout)return 65;fs.output=stateout;fs.output_capacity=RYZ_FS_SNAPSHOT_MAX;}
    config.execs=grants;file=fopen(argv[first],"rb");if(!file || fseek(file,0,SEEK_END))return 65;
    n=ftell(file);if(n<=0 || n>RYZ_PROCESS_IMAGE_MAX || fseek(file,0,SEEK_SET))return 65;
    total_image_bytes=(size_t)n;
    image=malloc((size_t)n);arena=malloc(RYZ_PROCESS_MAX_SPAN);if(!image || !arena)return 65;
    if(fread(image,1,(size_t)n,file)!=(size_t)n)return 65;
    fclose(file);args.argv=(const char *const *)(argv+first);args.argc=(size_t)(argc-first);args.envp=env;args.envc=2;
    for(gi=0;gi<config.exec_count;gi++){
        grants[gi].path=texts[gi];eq=strchr(texts[gi],'=');
        if(eq){
            unsigned char *bytes;long length;
            *eq=0;file=fopen(eq+1,"rb");if(!file || fseek(file,0,SEEK_END))return 65;
            length=ftell(file);if(length<=0 || length>RYZ_PROCESS_IMAGE_MAX ||
                (size_t)length>RYZ_PROCESS_IMAGE_TOTAL_MAX-total_image_bytes || fseek(file,0,SEEK_SET))return 65;
            total_image_bytes+=(size_t)length;
            bytes=malloc((size_t)length);if(!bytes || fread(bytes,1,(size_t)length,file)!=(size_t)length)return 65;
            fclose(file);grants[gi].image=bytes;grants[gi].size=(size_t)length;
        }else{grants[gi].image=image;grants[gi].size=(size_t)n;}
    }
    if(resources.resources.count && !config.root_tree)return 64;
    if(resources.resources.count){if(!resource_cli_prepare(&resources)){resource_cli_close(&resources);return 65;}config.resources=&resources.resources;}
    else if(resources.resources.view_count || resources.control)return 64;
    status=ryz_vm_run_jobs_elf(image,(size_t)n,arena,RYZ_PROCESS_MAX_SPAN,input?&files:NULL,&args,&config,sink,NULL,&result);
    fprintf(stderr,"COMPACT_JOBS_RESULT status=%d exited=%d exit=%u steps=%u syscalls=%u forks=%u execs=%u peak=%u blocked=%u pipebytes=%llu rip=%llx unsupported_syscall=%llu unsupported_syscall_valid=%d\n",status,result.exited,(unsigned)result.exit_status,(unsigned)result.executed_steps,(unsigned)result.syscall_count,(unsigned)result.forks,(unsigned)result.execs,(unsigned)result.peak_tasks,(unsigned)result.blocked_syscalls,(unsigned long long)result.pipe_bytes,(unsigned long long)result.last_rip,(unsigned long long)result.unsupported_syscall_nr,result.unsupported_syscall_valid);
    fprintf(stderr,"COMPACT_RESOURCE_STATS arena_peak=%llu shared_peak=%u\n",(unsigned long long)result.arena_peak_bytes,(unsigned)result.shared_peak_pages);
    fprintf(stderr,"COMPACT_GUEST_IO network_bytes=%llu resource_bytes=%llu output_bytes=%llu\n",(unsigned long long)result.network_bytes,(unsigned long long)result.resource_bytes,(unsigned long long)result.output_bytes);
    if(status==RYZ_VM_OK && result.exited && result.exit_status==0 && files.output_size)fwrite(out,1,files.output_size,stdout);
    if(stateoutpath && fs.output_size){
        file=fopen(stateoutpath,"wx");if(!file)return 65;
        if(fwrite(fs.output,1,fs.output_size,file)!=fs.output_size){fclose(file);remove(stateoutpath);return 65;}
        if(fclose(file)){remove(stateoutpath);return 65;}
    }
    resource_cli_close(&resources);
    free(statein);free(stateout);
    for(gi=0;gi<config.exec_count;gi++)if(grants[gi].image!=image)free((void *)grants[gi].image);
    free(image);free(arena);free(input);free(out);return status==RYZ_VM_OK && result.exited && result.exit_status==0?0:2;
}
