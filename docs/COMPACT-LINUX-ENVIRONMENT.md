# Compact Linux environment: bounded static file profile v1

This is an experimental artificial execution environment implemented as native
Ryzova/9front user-space applications. It completes a defined **file-workload
profile**, not general Linux application compatibility. It reuses the Phase 9.2
interpreter and preserves its legacy write/exit-only entry point.

## Implemented contract

| Surface | Version and behavior |
|---|---|
| Native launcher | `compact-linux [-i INPUT] ELF` |
| Discovery service | `compact-linux-fs MOUNTPOINT`, native read-only 9P |
| Discovery paths | `MOUNTPOINT/compact/linux/{api,abi,status,limits}` |
| API metadata | `compact/linux api=1.0 profile=files-v1` |
| Guest ABI profile | `linux-amd64-static-subset-v1` |
| Resources | `/input` read-only; `/output` write-only; exact relative `input` and `output` aliases with virtual cwd `/` |
| File syscalls | `read`, `write`, `openat`, `close` |
| Other syscalls | `getpid/getuid/getgid/gettid` return synthetic profile IDs; `exit`, `exit_group` |
| Instructions | Legacy subset plus register MOV/XOR, MOVABS, RIP-relative LEA, TEST/CMP, relative JMP and selected near conditional branches |
| Limits | 1 MiB ELF, 2 MiB mapped arena, 64 KiB input/output/stdio, 16 FDs, 65536 instructions |

The launcher creates a private namespace/environment group, snapshots only the
explicitly granted input file, and gives the guest per-invocation buffers. No
guest pathname is forwarded to the host filesystem. Unknown paths, traversal,
input writes, RX-segment writes, invalid handles and oversized operations fail.
Unsupported opcodes and syscalls stop execution. Supported syscall errors return
Linux negative errno to the guest so it can handle them. `/output` is exported to
stdout only after successful guest exit; direct guest stdout/stderr writes use
the existing callback and a separate combined 64 KiB quota.

Each open has its own offset. Close/reopen reuses slots with offset zero.
`O_TRUNC` is accepted only for `/output`; its whole bounded buffer is cleared.
`O_CREAT`, `O_RDWR`, directory FDs other than `AT_FDCWD`, arbitrary directory
trees, symlinks and host filesystem passthrough are absent. The descriptor table
is not a host FD table. Metadata advertises this profile and grants no execution
or resource access. Phase 9.1 Python negotiation is still a separate contract.

## Build and run on an AMD64 Ryzova/9front guest

Copy this checkout's `ryzova/compat/linux` to `/sys/src/cmd/compact-linux`:

```
cd /sys/src/cmd/compact-linux
mk install
cd service
mk install
mkdir -p /tmp/flex-environment
compact-linux-fs /tmp/flex-environment
cat /tmp/flex-environment/compact/linux/api
cat /tmp/flex-environment/compact/linux/abi
compact-linux -i /path/to/input /path/to/copy.elf > /tmp/result
```

To expose `/compact/linux`, append this service root to a private root namespace
using Plan 9 `bind -a`. The native CI does this inside its disposable guest and
reads the real mounted paths; this is not a host-side mock directory.

## Reproducible workload and evidence

`scripts/phase9_linux_environment.py` constructs a real static ELF that opens
input/output, copies binary data through a writable buffer in repeated reads,
checks errors, closes both FDs and exits. The exact same ELF runs on Linux with
`input` and a pre-existing `output` in its cwd. Differential tests compare empty,
partial-block, multi-block and maximum-size results byte for byte. It is a small
purpose-built workload, not BusyBox, glibc or evidence of arbitrary Linux apps.

The mandatory Phase 3 CI builds both native applications, syncs hjfs, reboots
the freshly source-built kernel, mounts the service, checks read-only metadata,
and runs copy/permission/traversal/RX-write-denial workloads. It compares output
SHA256 to binary input tied to the exact source commit, repeats execution with
the previous output as a fresh input, and tests failure without file-profile
opt-in. Report: `artifacts/phase3/phase9-linux-environment.json`.

Host tests additionally cover FD exhaustion/recovery, per-process offsets and
output separation, output capacity, oversized inputs, malformed ELF output reset,
instruction limits and false serial evidence. Existing Phase 5 and Phase 9.2
checks, native AMD64 provenance, driver, guest mTLS and security gates remain.

## Remaining work toward general Linux compatibility

Dynamic ELF linking, libc/runtime support, a general instruction engine or native
syscall trap path, Linux process startup stack/argv/env/auxv, mmap/brk/mprotect,
fork/exec/wait, threads/futexes, signals, general files/stat/directories, sockets,
poll/epoll, clocks, GUI/audio and broad application qualification remain. This
profile does not claim POSIX certification, a production security sandbox,
remote resource grants, general Linux support or physical hardware qualification.
Windows and macOS environments remain separate work.
