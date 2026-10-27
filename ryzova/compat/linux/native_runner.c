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
    int fd, status;
    long n;
    size_t used;
    unsigned char *image, *arena;
    RyzVmResult result;

    if(argc != 2){
        fprint(2, "usage: compact-linux static-linux-amd64-elf\n");
        exits("usage");
    }
    fd = open(argv[1], OREAD);
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
    status = ryz_vm_run_static_elf(image, used, arena, RYZ_VM_MAX_SPAN,
                                  output, nil, &result);
    fprint(2, "COMPACT_LINUX_RESULT status=%d exited=%d exit=%ud steps=%ud syscalls=%ud\n",
        status, result.exited, (uint)result.exit_status,
        (uint)result.executed_steps, (uint)result.syscall_count);
    free(arena);
    free(image);
    exits(status == RYZ_VM_OK && result.exited && result.exit_status == 0
          ? nil : "guest execution failed");
}
