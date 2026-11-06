/* SPDX-License-Identifier: AGPL-3.0-only */
#include <u.h>
#include <libc.h>
#include "m8_start.h"

void
main(int argc, char **argv)
{
    int fd, status;
    long bytes;
    unsigned char *image, *arena;
    uvlong guard;
    Mac8Stop result;

    if(argc!=3 || strcmp(argv[1], "--version"))
        sysfatal("usage: compact-macos-m8 --version MACH-O");
    fd = open(argv[2], OREAD);
    if(fd<0)
        sysfatal("open executable: %r");
    image = malloc(Mac8Limit+1);
    arena = malloc(Mac8ArenaBytes);
    if(!image || !arena)
        sysfatal("allocate guest arenas");
    bytes = readn(fd, image, Mac8Limit+1);
    close(fd);
    if(bytes<=0 || bytes>Mac8Limit)
        sysfatal("read bounded executable: %r");

    fd = open("/dev/random", OREAD);
    if(fd<0 || readn(fd, &guard, sizeof guard)!=sizeof guard || !guard)
        sysfatal("initialize guest stack guard: %r");
    close(fd);
    memset(&result, 0, sizeof result);
    status = mac8_start(image, bytes, arena, Mac8ArenaBytes, guard, &result);
    if(status!=2)
        sysfatal("M8 stopped at %llux after %ud steps (%d)", result.last_pc, result.steps, status);
    if(write(1, result.stdout_data, result.stdout_bytes)!=result.stdout_bytes)
        sysfatal("write guest stdout: %r");
    if(result.exit_code)
        exits(smprint("guest exit %ud", result.exit_code));
    exits(nil);
}
