/* SPDX-License-Identifier: AGPL-3.0-only */
/* Native Plan 9 user-space application; interprets a bounded Linux ELF subset. */
#include "process.h"
#define IMAGE_LIMIT (1024U * 1024U)

static int64_t
output(void *context, int fd, const unsigned char *bytes, size_t size)
{
    USED(context);
    return write(fd, bytes, size);
}

void
main(int argc, char **argv)
{
    int fd, status, filemode, processmode, argi;
    const char *env[RYZ_PROCESS_ARGS];
    RyzProcessArgs args;
    long n;
    size_t used;
    unsigned char *image, *arena, *input, *fileout;
    char *imagepath, *inputpath;
    RyzLinuxFiles files;
    RyzVmResult result;

    filemode=processmode=0; inputpath=nil; argi=1;
    memset(&args,0,sizeof args);
    while(argi<argc){
        if(strcmp(argv[argi],"-p")==0){ processmode=1; argi++; }
        else if(strcmp(argv[argi],"-i")==0 && argi+1<argc && !filemode){
            filemode=1; inputpath=argv[argi+1]; argi+=2;
        }else if(strcmp(argv[argi],"-e")==0 && argi+1<argc && args.envc<RYZ_PROCESS_ARGS){
            env[args.envc++]=argv[argi+1]; argi+=2;
        }else if(strcmp(argv[argi],"--")==0){ argi++; break; }
        else break;
    }
    if(argi>=argc || (!processmode && (argc-argi!=1 || args.envc!=0))){
        fprint(2, "usage: compact-linux [-p [-e KEY=VALUE]] [-i input-file] ELF [args...]\n");
        exits("usage");
    }
    if(rfork(RFNAMEG|RFENVG) < 0)
        sysfatal("private process namespace: %r");
    imagepath=argv[argi];
    args.argv=(const char *const *)(argv+argi); args.argc=argc-argi;
    args.envp=env;
    input = fileout = nil;
    memset(&files, 0, sizeof files);
    fd = open(imagepath, OREAD);
    if(fd < 0)
        sysfatal("open input: %r");
    image = malloc(IMAGE_LIMIT + 1);
    arena = malloc(RYZ_VM_MAX_SPAN);
    if(image == nil || arena == nil)
        sysfatal("allocate bounded runtime: %r");
    used = 0;
    while(used < IMAGE_LIMIT + 1){
        n = read(fd, image + used, IMAGE_LIMIT + 1 - used);
        if(n < 0)
            sysfatal("read input: %r");
        if(n == 0)
            break;
        used += n;
    }
    close(fd);
    if(used == 0 || used > IMAGE_LIMIT)
        sysfatal("input outside 1..1048576 byte limit");
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
        if(processmode)
            status=ryz_vm_run_process_elf(image,used,arena,RYZ_VM_MAX_SPAN,&files,&args,output,nil,&result);
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
    }else if(processmode)
        status=ryz_vm_run_process_elf(image,used,arena,RYZ_VM_MAX_SPAN,nil,&args,output,nil,&result);
    else
        status = ryz_vm_run_static_elf(image, used, arena, RYZ_VM_MAX_SPAN,
                                      output, nil, &result);
    fprint(2, "COMPACT_LINUX_RESULT status=%d exited=%d exit=%ud steps=%ud syscalls=%ud\n",
        status, result.exited, (uint)result.exit_status,
        (uint)result.executed_steps, (uint)result.syscall_count);
    if(processmode && status != RYZ_VM_OK)
        fprint(2,"COMPACT_PROCESS_FAULT rip=%llux\n",result.last_rip);
    free(input);
    free(fileout);
    free(arena);
    free(image);
    exits(status == RYZ_VM_OK && result.exited && result.exit_status == 0
          ? nil : "guest execution failed");
}
