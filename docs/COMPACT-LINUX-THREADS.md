# Cooperative Linux threads

The `compact-linux -j` interpreter implements a bounded AMD64 Linux thread
family using guest memory and guest instructions. No host clone, pthread or
futex operation executes on behalf of an application. This extends the dynamic
runtime in [COMPACT-LINUX-RUNTIME.md](COMPACT-LINUX-RUNTIME.md).

The supported clone profile shares VM, files, filesystem state and signal
actions, with distinct TIDs, shared TGID, per-thread signal masks and guest TLS.
It implements parent/child TID stores, child-TID clearing/wake, scheduling yield,
thread exit, process exit, and process replacement from either the leader or a
worker. Successful worker exec retains the process PID and replaces all siblings;
a failed exec leaves the original process runnable. CLOEXEC descriptors close,
ignored signal actions and the caller's signal mask survive, and caught actions
reset. Shared resources remain owned until their final user releases them.

Futex support includes wait/wake, bitsets, relative and absolute logical
timeouts, requeue and comparison/requeue. Signal interruption and SA_RESTART
retain the original deadline. Robust-list cleanup marks owner death and wakes
waiters, with a 2048-node traversal limit. Priority inheritance, futex2 and
cross-invocation shared memory are unsupported. Execution is cooperative, with
no native parallel execution or performance equivalence claim.

Address spaces live in a separate reference-counted pool. Reaping or reusing a
Task slot cannot rebind a still-running vfork child to another process's memory.
Vfork wakeups check parent identity and a wait-generation token, including after
exec retains a PID. Memory-barrier registration is per address space.

The group retains the existing 8-live-task and 32-cumulative-creation limits;
processes and threads consume the same pool. All work shares the instruction
budget and 16 MiB address-space bound. The logical clock saturates rather than
wrapping. Stopped tasks' periodic timers cannot spin the host scheduler. Native
entropy is limited to 1 MiB per invocation, including AT_RANDOM.

Qualification includes real unmodified musl pthread creation/join, mutexes,
condition variables, TLS, shared descriptors/cwd/umask/actions, robust mutexes,
cancellation, detach, directed signals, worker fork/exec, creation limits and
raw syscall regressions. Supported cases are compared with Linux and repeated
under address/undefined sanitizers. Virtual policy limits use explicit expected
results instead of treating host Linux limits as equivalent.

`scripts/phase9_threads.py` adds a fresh source-built-kernel qualification gate.
It requires source-specific guest challenges, independently checked fixture
hashes, successful result records and every workload marker. A host-only pass
must not be reported as a native-kernel pass.

Full Linux application compatibility remains unfinished: general sockets and
network grants, persistent/general mounts, broader ISA/terminal support and
complete Python/Git/SDK workloads still need implementation and qualification.
Physical hardware and operational ARM64 remain unqualified. This work is not an
authorization to merge the cumulative draft pull requests.
