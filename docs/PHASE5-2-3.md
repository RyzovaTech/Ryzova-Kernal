<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.2–5.3 — Linux ABI virtual process and namespace foundations

**Experimental isolated C modules. Do not merge into main until full Phase 5.**

## Phase 5.2 — Linux AMD64 syscall dispatcher

`syscall.c` implements *simulated* per-process guest memory and Linux x86-64 syscall register ABI. It reads syscall number from `rax` and arguments from `rdi`, `rsi`, `rdx` (future arg 4–6: `r10`, `r8`, `r9`). All return values use Linux negative errno, never host errno.

Implemented narrow set: `read(0)`, `write(1)`, `close(3)`, `getpid(39)`, `exit(60)`, `getuid(102)`, `getgid(104)`, `gettid(186)`, `exit_group(231)`, `openat(257)`. Unsupported calls return `-ENOSYS` (38). `gettid` equals virtual pid because no threads exist. Credentials are explicitly supplied to the simulated state; **they do not grant Plan 9 privileges**.

`read` supports simulated stdin EOF and virtual `/dev/zero`, `/dev/null`; `write` supports virtual `/dev/null`, `/dev/zero`, or user-injected stdout/stderr callbacks. There is **no passthrough to real host or native kernel files**. Each I/O is capped at 64 KiB with checked guest-address-to-buffer conversion, virtual file descriptors are scoped to one process (16 slots), `openat` accepts only absolute allowlisted paths with `AT_FDCWD`, `O_RDONLY/O_WRONLY` and optional `O_CLOEXEC`. Unknown flags, privilege-sensitive paths, memory overflows and traversal are rejected. Terminal `exit` state blocks subsequent syscalls.

## Phase 5.3 — virtual `/compat/linux` namespace

`namespace.c` is a **pure namespace policy resolver**: per-process ID/credential state with optional `/compat/linux` prefix and virtual nodes `/dev/null`, `/dev/zero`, `/proc/self` and `/tmp`. The latter two are **only descriptors**, not mounted filesystems or implemented read/write providers. The resolver refuses relative paths, `..` traversal, unknown nodes, unsafe characters and oversized paths. It NEVER mounts Plan 9 namespaces and does not expose host or native filesystem resources.

## Verification and limits

`tests/test_phase5_runtime.py` compiles portable C and runs positive and malicious-input tests with GCC and Clang, with UndefinedBehaviorSanitizer. It also compiles with freestanding C flags to identify host-ABI coupling. The independent 9front source-built QEMU CI continues to check no kernel regressions.

These modules do **not** yet integrate with Ryzova's native trap handler, process allocator, MMU page mappings or kernel syscall path. No native Linux binary is executed; ELF Phase 5.1 planner is not yet linked to real process construction. Linux `mmap`, stack/auxv, TLS, signals, threads, network, real `/proc` and dynamic loaders remain unimplemented. **Phase 5.4 must supply a real execution integration and QEMU application proof before Linux compatibility may be claimed.**

Do not merge or publish a kernel binary on the basis of this host-only compatibility prototype.
