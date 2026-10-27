/* SPDX-License-Identifier: AGPL-3.0-only */
/* Native Plan 9 user-space application; interprets a bounded Linux ELF subset. */
#include "subset_vm.h"
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
    int fd, status, filemode;
    long n;
    size_t used;
    unsigned char *image, *arena, *input, *fileout;
    char *imagepath, *inputpath;
    RyzLinuxFiles files;
    RyzVmResult result;

    filemode = argc == 4 && strcmp(argv[1], "-i") == 0;
    if(argc != 2 && !filemode){
        fprint(2, "usage: compact-linux [-i input-file] static-linux-amd64-elf\n");
        exits("usage");
    }
    if(rfork(RFNAMEG|RFENVG) < 0)
        sysfatal("private process namespace: %r");
    imagepath = filemode ? argv[3] : argv[1];
    inputpath = filemode ? argv[2] : nil;
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
    }else
        status = ryz_vm_run_static_elf(image, used, arena, RYZ_VM_MAX_SPAN,
                                      output, nil, &result);
    fprint(2, "COMPACT_LINUX_RESULT status=%d exited=%d exit=%ud steps=%ud syscalls=%ud\n",
        status, result.exited, (uint)result.exit_status,
        (uint)result.executed_steps, (uint)result.syscall_count);
    free(input);
    free(fileout);
    free(arena);
    free(image);
    exits(status == RYZ_VM_OK && result.exited && result.exit_status == 0
          ? nil : "guest execution failed");
}
