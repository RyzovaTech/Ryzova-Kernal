/* SPDX-License-Identifier: AGPL-3.0-only */
#include <u.h>
#include <libc.h>
#include "m8_start.h"

static unsigned char *
read_file(char *path, unsigned int *size, int empty_ok)
{
    int fd;
    long bytes;
    unsigned char *data;
    fd = open(path, OREAD);
    if(fd<0)
        sysfatal("open %s: %r", path);
    data = malloc(Mac8Limit+1);
    if(!data)
        sysfatal("allocate bounded file buffer");
    bytes = readn(fd, data, Mac8Limit+1);
    close(fd);
    if(bytes<0 || (!bytes && !empty_ok) || bytes>Mac8Limit)
        sysfatal("read bounded file %s: %r", path);
    *size = bytes;
    return data;
}

void
main(int argc, char **argv)
{
    static const char *query[] = {
        "jq", "-c", "{count: (.items | length), sum: (.items | add)}", "input.json"
    };
    int fd, status, version;
    unsigned int image_bytes, input_bytes = 0;
    unsigned char *image, *arena, *input = nil;
    uvlong guard;
    Mac8Stop result;

    version = argc==3 && !strcmp(argv[1], "--version");
    if(!version && (argc!=4 || strcmp(argv[1], "--query")))
        sysfatal("usage: compact-macos-m8 --version MACH-O or --query MACH-O INPUT");
    image = read_file(argv[2], &image_bytes, 0);
    if(!version)
        input = read_file(argv[3], &input_bytes, 1);
    arena = malloc(Mac8ArenaBytes);
    if(!arena)
        sysfatal("allocate guest arena");

    fd = open("/dev/random", OREAD);
    if(fd<0 || readn(fd, &guard, sizeof guard)!=sizeof guard || !guard)
        sysfatal("initialize guest stack guard: %r");
    close(fd);
    /* Match the guest profile's initial IEEE rounding and exception masks. */
    setfcr(FPRNR);
    setfsr(0);
    memset(&result, 0, sizeof result);
    if(version)
        status = mac8_start(image, image_bytes, arena, Mac8ArenaBytes, guard, &result);
    else
        status = mac8_run(image, image_bytes, arena, Mac8ArenaBytes, guard,
                          nelem(query), query, Mac8MaxBudget, input, input_bytes, &result);
    if(status!=2)
        sysfatal("M8 stopped at %llux after %ud steps (%d)", result.last_pc, result.steps, status);
    if(write(1, result.stdout_data, result.stdout_bytes)!=result.stdout_bytes ||
       write(2, result.stderr_data, result.stderr_bytes)!=result.stderr_bytes)
        sysfatal("write guest output: %r");
    if(result.exit_code)
        exits(smprint("guest exit %ud", result.exit_code));
    exits(nil);
}
