/* SPDX-License-Identifier: AGPL-3.0-only */
/* Read-only native 9P discovery service. It never dispatches guest execution. */
#include <u.h>
#include <libc.h>
#include <fcall.h>
#include <9p.h>

static Srv fs;
static char api[] = "compact/linux api=1.0 profile=files-v1\n"
    "launch=compact-linux -i INPUT ELF\ninput=/input:read output=/output:write\n";
static char abi[] = "linux-amd64-static-subset-v1\n"
    "syscalls=read,write,openat,close,getpid,getuid,getgid,gettid,exit,exit_group\n"
    "instruction-set=bounded-subset dynamic-linker=none threads=none signals=none\n";
static char status[] = "experimental bounded-file-profile\n"
    "general-linux-compatibility=false windows=false mac=false\n"
    "metadata-is-not-authorization=true\n";
static char limits[] = "image=1048576 arena=2097152 input=65536 output=65536 fds=16 steps=65536\n";

static void
fsread(Req *r)
{
    readstr(r, r->fid->file->aux);
    respond(r, nil);
}
static void
leaf(File *parent, char *name, char *data)
{
    File *f;
    f = createfile(parent, name, getuser(), 0444, data);
    if(f == nil)
        sysfatal("create metadata: %r");
    f->length = strlen(data);
    closefile(f);
}
void
main(int argc, char **argv)
{
    char *mountpoint;
    File *compact, *linux;
    if(argc != 2){
        fprint(2, "usage: compact-linux-fs mountpoint\n");
        exits("usage");
    }
    mountpoint = argv[1];
    fs.tree = alloctree(getuser(), getuser(), DMDIR|0555, nil);
    if(fs.tree == nil)
        sysfatal("allocate tree: %r");
    compact = createfile(fs.tree->root, "compact", getuser(), DMDIR|0555, nil);
    if(compact == nil)
        sysfatal("create compact: %r");
    linux = createfile(compact, "linux", getuser(), DMDIR|0555, nil);
    if(linux == nil)
        sysfatal("create linux: %r");
    leaf(linux, "api", api);
    leaf(linux, "abi", abi);
    leaf(linux, "status", status);
    leaf(linux, "limits", limits);
    closefile(linux);
    closefile(compact);
    fs.read = fsread;
    postmountsrv(&fs, nil, mountpoint, MREPL);
    exits(nil);
}
