/* SPDX-License-Identifier: AGPL-3.0-only */
/* Read-only native 9P discovery service. It never dispatches guest execution. */
#include <u.h>
#include <libc.h>
#include <fcall.h>
#include <thread.h>
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
static char process[] = "linux-amd64-compiler-static-v1\nstartup=argc,argv,explicit-envp,auxv stack=65536\n"
    "memory=brk,anonymous-mmap,mprotect,munmap executable-anonymous-memory=false\n"
    "integer-instruction-subset=true libc=selected-static-musl TLS-segment-base=true vector=copy,xor threads=false signals=state-only\n";
static char limits[] = "image=1048576 arena=2097152 input=65536 output=65536 stdio=65536 fds=16 steps=65536\n"
    "process-image=4194304 process-arena=16777216 process-steps=262144\n";
static char jobs[] = "linux-amd64-static-jobs-v1\n"
    "launch=compact-linux -j -x guest-path[=host-ELF] ELF args\n"
    "processes=8 forks=32 execs=64 descriptors=16 shared-descriptions=64 pipes=4 pipe-bytes=4194304\n"
    "fork=private-memory vfork=shared-memory-parent-suspended exec=explicit-image-grants wait=normal-child-exit\n"
    "threads=false asynchronous-signals=false dynamic-linker=false general-linux=false\n";
static char filesystem[] = "linux-amd64-local-tmp-v1\n"
    "profile=jobs path=/tmp lifetime=one-invocation shared=fork,exec host-forwarding=false\n"
    "nodes=32 file-bytes=65536 permissions=owner timestamps=logical-clock symlinks=false hardlinks=false\n";
static char runtime[] = "linux-amd64-runtime-v1\n"
    "launch=compact-linux -j ELF args signals=guest-rt-frame,mask,kill,wait,altstack\n"
    "signal-depth=8 realtime-queue=33 per-task-standard-signals=coalesced\n"
    "dynamic=explicit-interpreter-and-library-grants pie=true tls=guest-linker\n"
    "time=logical-microsecond-per-instruction timers=alarm,setitimer,nanosleep,sigtimedwait\n"
    "entropy=native-OS-capability,1MiB-group-limit threads=cooperative sockets=local-streams,explicit-TCP-resources general-linux=false\n";
static char network[] = "linux-amd64-tcp-resources-v1\n"
    "grant=guest-IP:port=tcp!native-host!port routing=exact-explicit-grant\n"
    "limits=4-grants,1-connection-per-grant,4MiB-traffic,5000ms-default,10000ms-max\n"
    "backend=native-Plan9-dial,conservative-readiness dns=caller-dial-only\n"
    "guest-dns=false udp=false external-listen=false external-half-write-close=false\n";
static char persistence[] = "linux-amd64-filesystem-snapshot-v1\n"
    "launch=compact-linux -j -R snapshot-in -W new-snapshot-out ELF args\n"
    "scope=/tmp format=FLEXFS1 permissions=0600 export=exclusive-create\n"
    "validation=checksum,topology,names,inodes,bounds auth=none\n"
    "general-host-mounts=false crash-atomic-replace=false\n";
static char sockets[] = "linux-amd64-local-sockets-v1\n"
    "domain=unix-abstract,ipv4-loopback type=stream namespace=invocation-private\n"
    "operations=pair,bind,listen,connect,accept,read,write,sendmsg,recvmsg,poll,shutdown\n"
    "limits=32-endpoints,16-fds-per-table,8-backlog,4096-rx-bytes,4MiB-traffic\n"
    "external-network=false dns=false datagram=false ancillary-fd-passing=false\n";
static char threads[] = "linux-amd64-threads-v1\n"
    "clone=shared-mm,files,fs,sighand,tls tids=synthetic thread-group=true\n"
    "futex=wait,wake,bitset,requeue,timeout robust=owner-died clear-child-tid=true\n"
    "limits=8-live-tasks,32-cumulative-creations priority-inheritance=false\n"
    "exec=group-replacement scheduling=cooperative native-parallel=false\n";
static char shell[] = "experimental-bounded-ash-v1\n"
    "workloads=script,variables,loops,functions,conditionals,input,output,append,cat,wc\n"
    "paths=/input:read,/output:write cwd=/,/tmp descriptors=16\n"
    "fork=false exec=false pipes=false asynchronous-signals=false general-linux=false\n";

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
    leaf(linux, "process", process);
    leaf(linux, "shell", shell);
    leaf(linux, "jobs", jobs);
    leaf(linux, "filesystem", filesystem);
    leaf(linux, "runtime", runtime);
    leaf(linux, "threads", threads);
    leaf(linux, "sockets", sockets);
    leaf(linux, "persistence", persistence);
    leaf(linux, "network", network);
    closefile(linux);
    closefile(compact);
    fs.read = fsread;
    postmountsrv(&fs, nil, mountpoint, MREPL);
    exits(nil);
}
