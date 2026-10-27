# Compact Linux compiled-process profile v1

This adds a separate opt-in process path to the native Compact application:

```
compact-linux -p -e 'FLEX_MODE=test' /path/to/static-elf argument
compact-linux -p -i /path/to/input /path/to/static-elf argument
```

The established legacy and bounded-file profiles remain separate entry points.
`-p` enables a 64 KiB guest stack with an unmapped guard page, argc/argv,
explicit envp and a small auxiliary vector. Environment variables are never
implicitly copied from the native host. Up to 16 arguments and 16 environment
strings, each at most 256 bytes, are accepted. The auxiliary vector contains
PHDR/PHENT/PHNUM, PAGESZ, ENTRY and synthetic UID/EUID/GID/EGID plus its null
terminator. Program headers must be mapped readable. There is no AT_RANDOM,
vDSO, interpreter or TLS setup; this is not libc-ready.

## Execution and memory

The new bounded integer AMD64 interpreter supports the tested scalar register,
memory, stack, CALL/RET, arithmetic/flags, conditional branch and syscall
instructions needed by the compiled fixture. It has 16 integer registers,
ModRM/SIB addressing, guarded memory operands and a 262144-instruction budget.
Unsupported encodings, SIMD/floating point, division, atomics and TLS accesses
stop execution. This is not a complete x86-64 CPU implementation.

`brk` and anonymous private `mmap` provide zeroed pages inside the same 2 MiB
arena. `mprotect` and `munmap` operate only on the anonymous mmap area; image,
brk and stack protection changes are outside this profile. Anonymous executable
memory, fixed mappings, shared/file mappings and unsupported mmap flags are
rejected. Failed multi-page mprotect validates the entire range before mutation.
Reads, writes, instruction fetches and syscall buffers obey page permissions.
Reclaimed pages are cleared. No guest memory syscall reaches the host kernel.

## Evidence

`tests/fixtures/compact_process.c` is ordinary freestanding C with thin inline
Linux syscall wrappers. GCC and the system linker build it as static ELF,
using `compact_process_start.S` for entry. The exact same binary runs on Linux
and through this interpreter. It validates argument/environment termination,
auxv including entry/PHDR, function calls, stack, integer loops, mmap,
mprotect, munmap, brk and source-specific console output. The build intentionally
disables SIMD, stack protector and dynamic linking; it is not an unmodified
third-party application compatibility benchmark.

The mandatory native workflow compiles the runtime with the guest Plan 9
toolchain, reboots the freshly source-built kernel, transfers the GCC ELF,
executes it using `compact-linux -p`, and requires the C-program marker,
source-commit argument challenge, 13 expected syscalls, successful exit and
guest/host ELF SHA256 equality. A further run verifies the existing file-copy ELF through the new process
path with an explicit input grant. Existing file-profile and authenticated remote
resource tests remain mandatory. Report: `phase9-linux-process.json`.

Host tests compare Unicode and boundary-size arguments, reject oversized
argument vectors, verify no implicit environment inheritance, and exercise
page permission/overflow/reclamation and false serial evidence cases with UBSan.

## Remaining compatibility work

General Linux compatibility remains unfinished: complete instruction coverage,
dynamic ELF/libc/TLS, richer startup auxv, signals, threads/futexes, fork/exec/wait,
general files/directories/stat, sockets/poll/epoll, clocks, GUI/audio and broad
real-world application qualification. This profile is not a production security
sandbox or a physical hardware qualification. No general Linux completion is
claimed by this milestone.

Process-entry references (design input, not a conformance certification):

- AMD64 psABI process initialization: https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
- Linux ELF loading/auxv: https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git/+/627b7865c062ff642c0000f3a4775f1a44b986a4/fs/binfmt_elf.c
