/* SPDX-License-Identifier: AGPL-3.0-only */
#include <u.h>
#include <libc.h>
#include "m8_start.h"

static unsigned char *
read_file(char *path, unsigned int *size, unsigned int limit, int empty_ok)
{
    int fd;
    long bytes;
    unsigned char *data;
    fd = open(path, OREAD);
    if(fd<0)
        sysfatal("open %s: %r", path);
    data = malloc(limit+1);
    if(!data)
        sysfatal("allocate bounded file buffer");
    bytes = readn(fd, data, limit+1);
    close(fd);
    if(bytes<0 || (!bytes && !empty_ok) || bytes>limit)
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
    int fd, status, version = 0, at, guest_argc = 0;
    unsigned int image_bytes, input_bytes = 0;
    unsigned char *image, *arena, *input = nil;
    const char *alias = nil;
    char *image_path = nil, *input_path = nil;
    const char *const *guest_argv = nil;
    uvlong guard;
    Mac8Stop result;

    if(argc==3 && !strcmp(argv[1], "--version")){
        version = 1;
        image_path = argv[2];
    }else if(argc==4 && !strcmp(argv[1], "--query")){
        image_path = argv[2];
        alias = "input.json";
        input_path = argv[3];
        guest_argc = nelem(query);
        guest_argv = query;
    }else if(argc>=5 && !strcmp(argv[1], "--run")){
        at = 2;
        if(argc>=8 && !strcmp(argv[at], "--read-only")){
            alias = argv[at+1];
            input_path = argv[at+2];
            if(!mac9_grant_name(alias))
                sysfatal("invalid read-only guest basename");
            at += 3;
        }
        if(argc-at<3 || strcmp(argv[at+1], "--") || !argv[at+2][0])
            sysfatal("expected MACH-O -- ARGV0 [ARG ...]");
        image_path = argv[at];
        guest_argc = argc-at-2;
        guest_argv = (const char *const *)(argv+at+2);
    }else
        sysfatal("usage: compact-macos-m8 --run [--read-only NAME FILE] MACH-O -- ARGV0 [ARG ...]");
    image = read_file(image_path, &image_bytes, Mac8Limit, 0);
    if(input_path)
        input = read_file(input_path, &input_bytes, Mac8InputLimit, 1);
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
        status = mac9_run(image, image_bytes, arena, Mac8ArenaBytes, guard,
                          guest_argc, guest_argv, Mac8MaxBudget, alias, input, input_bytes, &result);
    if(status!=2){
        fprint(2, "M8 fault pc=%llux token=%llux link=%llux args=%llux,%llux,%llux,%llux output=%ud,%ud\n",
               result.last_pc, result.pc, result.link, result.arg0, result.arg1,
               result.arg2, result.arg3, result.stdout_bytes, result.stderr_bytes);
        sysfatal("M8 stopped after %ud steps (%d)", result.steps, status);
    }
    if(write(1, result.stdout_data, result.stdout_bytes)!=result.stdout_bytes ||
       write(2, result.stderr_data, result.stderr_bytes)!=result.stderr_bytes)
        sysfatal("write guest output: %r");
    if(result.exit_code)
        exits(smprint("guest exit %ud", result.exit_code));
    exits(nil);
}
