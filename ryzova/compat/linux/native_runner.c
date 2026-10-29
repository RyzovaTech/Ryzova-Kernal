/* SPDX-License-Identifier: AGPL-3.0-only */
/* Native Plan 9 user-space application; interprets a bounded Linux ELF subset. */
#include "jobs.h"
#include <libsec.h>
#include "network_plan9.h"
#define IMAGE_LIMIT (1024U * 1024U)

static unsigned char *
readimage(char *path,size_t limit,size_t *size)
{
    unsigned char *bytes;int fd;long n;
    fd=open(path,OREAD);if(fd<0)sysfatal("open executable grant: %r");
    bytes=malloc(limit+1);if(bytes==nil)sysfatal("allocate image: %r");
    *size=0;
    while(*size<limit+1){n=read(fd,bytes+*size,limit+1-*size);if(n<0)sysfatal("read executable grant: %r");if(!n)break;*size+=n;}
    close(fd);if(*size==0 || *size>limit)sysfatal("executable grant exceeds image limit");return bytes;
}

static int64_t
output(void *context, int fd, const unsigned char *bytes, size_t size)
{
    USED(context);
    if(fd>=0 && fd<3 && !network_stdio[fd])return -1;
    return write(fd, bytes, size);
}

static int64_t entropy(void *context,unsigned char *bytes,size_t size)
{
    (void)context;genrandom(bytes,(int)size);return (int64_t)size;
}
void
main(int argc, char **argv)
{
    int fd, status, filemode, processmode, jobsmode, argi;
    const char *env[RYZ_PROCESS_ARGS];
    char *grant_text[RYZ_PROCESS_ARGS],*eq;
    RyzLinuxExec grants[RYZ_PROCESS_ARGS];
    size_t gi;
    RyzJobConfig config;RyzFilesystemResources filesystem;char *stateinpath=nil,*stateoutpath=nil;unsigned char *statein=nil,*stateout=nil;
    RyzNetworkResources network;RyzNetworkGrant network_grants[RYZ_NETWORK_GRANTS];NetworkHost network_hosts[RYZ_NETWORK_GRANTS];
    RyzProcessArgs args;
    long n;
    size_t used, image_limit, arena_limit;
    unsigned char *image, *arena, *input, *fileout;
    char *imagepath, *inputpath;
    RyzLinuxFiles files;
    RyzVmResult result;

    memset(&network,0,sizeof network);memset(network_grants,0,sizeof network_grants);network.grants=network_grants;network.now_ns=network_now;network.wait=network_wait;
    memset(&filesystem,0,sizeof filesystem);
    filemode=processmode=jobsmode=0;
    memset(&config,0,sizeof(config));config.random=entropy;config.execs=grants;memset(grants,0,sizeof(grants)); inputpath=nil; argi=1;
    memset(&args,0,sizeof args);
    while(argi<argc){
        if(strcmp(argv[argi],"-j")==0){jobsmode=processmode=1;argi++;}
        else if(strcmp(argv[argi],"-b")==0 && argi+1<argc){
            char *end;ulong n=strtoul(argv[argi+1],&end,10);if(!n || n>16777216 || *end)sysfatal("invalid instruction budget");config.max_steps=(uint32_t)n;argi+=2;
        }else if(strcmp(argv[argi],"-n")==0 && argi+1<argc && network.count<RYZ_NETWORK_GRANTS){
            if(!network_parse(argv[argi+1],&network_grants[network.count],&network_hosts[network.count]))sysfatal("invalid TCP resource grant");
            network.count++;argi+=2;
        }else if(strcmp(argv[argi],"-t")==0 && argi+1<argc){char *end;ulong value=strtoul(argv[argi+1],&end,10);if(*end || !value || value>10000)sysfatal("invalid network time budget");network.wall_milliseconds=(unsigned int)value;argi+=2;
        }else if(strcmp(argv[argi],"-R")==0 && argi+1<argc && !stateinpath){stateinpath=argv[argi+1];argi+=2;
        }else if(strcmp(argv[argi],"-W")==0 && argi+1<argc && !stateoutpath){stateoutpath=argv[argi+1];argi+=2;
        }else if(strcmp(argv[argi],"-x")==0 && argi+1<argc && config.exec_count<RYZ_PROCESS_ARGS){grant_text[config.exec_count++]=argv[argi+1];argi+=2;}
        else if(strcmp(argv[argi],"-p")==0){ processmode=1; argi++; }
        else if(strcmp(argv[argi],"-i")==0 && argi+1<argc && !filemode){
            filemode=1; inputpath=argv[argi+1]; argi+=2;
        }else if(strcmp(argv[argi],"-e")==0 && argi+1<argc && args.envc<RYZ_PROCESS_ARGS){
            env[args.envc++]=argv[argi+1]; argi+=2;
        }else if(strcmp(argv[argi],"--")==0){ argi++; break; }
        else break;
    }
    if(argi>=argc || (network.wall_milliseconds && !network.count) || ((config.exec_count || config.max_steps || stateinpath || stateoutpath || network.count || network.wall_milliseconds) && !jobsmode) || (!processmode && (argc-argi!=1 || args.envc!=0))){
        fprint(2, "usage: compact-linux [-p | -j [-x guest-path[=host-ELF]]] [-n guest-IP:port=tcp!host!port] [-t network-ms] [-R snapshot-in] [-W new-snapshot-out] [-e KEY=VALUE] [-i input-file] ELF [args...]\n");
        exits("usage");
    }
    if(rfork(RFNAMEG|RFENVG) < 0)
        sysfatal("private process namespace: %r");
    if(network.count){network_prepare();config.network=&network;}
    if(stateinpath || stateoutpath)config.filesystem=&filesystem;
    if(stateinpath){statein=readimage(stateinpath,RYZ_FS_SNAPSHOT_MAX,&filesystem.input_size);filesystem.input=statein;}
    if(stateoutpath){stateout=malloc(RYZ_FS_SNAPSHOT_MAX);if(!stateout)sysfatal("allocate filesystem export: %r");filesystem.output=stateout;filesystem.output_capacity=RYZ_FS_SNAPSHOT_MAX;}
    imagepath=argv[argi];
    args.argv=(const char *const *)(argv+argi); args.argc=argc-argi;
    args.envp=env;
    input = fileout = nil;
    memset(&files, 0, sizeof files);
    image_limit=processmode?RYZ_PROCESS_IMAGE_MAX:IMAGE_LIMIT;
    arena_limit=processmode?RYZ_PROCESS_MAX_SPAN:RYZ_VM_MAX_SPAN;
    image=readimage(imagepath,image_limit,&used);arena=malloc(arena_limit);
    if(arena==nil)sysfatal("allocate bounded runtime: %r");
    for(gi=0;gi<config.exec_count;gi++){
        grants[gi].path=grant_text[gi];eq=strchr(grant_text[gi],'=');
        if(eq){
            *eq=0;if(eq[1]==0)sysfatal("empty executable grant path");
            grants[gi].image=readimage(eq+1,RYZ_PROCESS_IMAGE_MAX,&grants[gi].size);
        }else{grants[gi].image=image;grants[gi].size=used;}
    }
    if(filemode){
        input = malloc(RYZ_LINUX_FILE_MAX + 1);
        fileout = malloc(RYZ_LINUX_FILE_MAX);
        if(input == nil || fileout == nil)
            sysfatal("allocate file resources: %r");
        fd = open(inputpath, OREAD);
        if(fd < 0)
            sysfatal("open input grant: %r");
        files.input_size = 0;
        while(files.input_size < RYZ_LINUX_FILE_MAX + 1){
            n = read(fd, input + files.input_size, RYZ_LINUX_FILE_MAX + 1 - files.input_size);
            if(n < 0)
                sysfatal("read input grant: %r");
            if(n == 0)
                break;
            files.input_size += n;
        }
        close(fd);
        if(files.input_size > RYZ_LINUX_FILE_MAX)
            sysfatal("input resource exceeds 65536 bytes");
        files.input = input;
        files.output = fileout;
        files.output_capacity = RYZ_LINUX_FILE_MAX;
        if(jobsmode)
            status=ryz_vm_run_jobs_elf(image,used,arena,arena_limit,&files,&args,&config,output,nil,&result);
        else if(processmode)
            status=ryz_vm_run_process_elf(image,used,arena,arena_limit,&files,&args,output,nil,&result);
        else
            status = ryz_vm_run_file_elf(image, used, arena, RYZ_VM_MAX_SPAN,
                                         &files, output, nil, &result);
        if(status == RYZ_VM_OK && result.exited && result.exit_status == 0){
            used = 0;
            while(used < files.output_size){
                n = write(1, fileout + used, files.output_size - used);
                if(n <= 0)
                    sysfatal("export output: %r");
                used += n;
            }
        }
        fprint(2, "COMPACT_FILES_RESULT bytes=%ud profile=files-v1\n", (uint)files.output_size);
    }else if(jobsmode)
        status=ryz_vm_run_jobs_elf(image,used,arena,arena_limit,nil,&args,&config,output,nil,&result);
    else if(processmode)
        status=ryz_vm_run_process_elf(image,used,arena,arena_limit,nil,&args,output,nil,&result);
    else
        status = ryz_vm_run_static_elf(image, used, arena, RYZ_VM_MAX_SPAN,
                                      output, nil, &result);
    fprint(2, "COMPACT_LINUX_RESULT status=%d exited=%d exit=%ud steps=%ud syscalls=%ud\n",
        status, result.exited, (uint)result.exit_status,
        (uint)result.executed_steps, (uint)result.syscall_count);
    if(jobsmode)fprint(2,"COMPACT_JOBS_STATS forks=%ud execs=%ud peak=%ud blocked=%ud pipebytes=%llud\n",(uint)result.forks,(uint)result.execs,(uint)result.peak_tasks,(uint)result.blocked_syscalls,(uvlong)result.pipe_bytes);
    if(processmode && status != RYZ_VM_OK)
        fprint(2,"COMPACT_PROCESS_FAULT rip=%llux\n",result.last_rip);
    if(stateoutpath && filesystem.output_size){
        fd=create(stateoutpath,OWRITE|OEXCL,0600);if(fd<0)sysfatal("create new filesystem snapshot (never overwrite): %r");
        used=0;while(used<filesystem.output_size){
            n=write(fd,stateout+used,filesystem.output_size-used);
            if(n<=0){close(fd);remove(stateoutpath);sysfatal("write filesystem snapshot: %r");}
            used+=(size_t)n;
        }
        if(close(fd)<0){remove(stateoutpath);sysfatal("close filesystem snapshot: %r");}
    }
    if(network.count)network_finish();
    free(statein);free(stateout);
    for(gi=0;gi<config.exec_count;gi++)if(grants[gi].image!=image)free((void *)grants[gi].image);
    free(input);
    free(fileout);
    free(arena);
    free(image);
    exits(status == RYZ_VM_OK && result.exited && result.exit_status == 0
          ? nil : "guest execution failed");
}
