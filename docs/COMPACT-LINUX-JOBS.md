# Compact Linux bounded process groups

The opt-in `-j` profile adds guest fork/vfork, explicit exec grants, wait4 and
blocking pipes to the native Compact user-space application. Processes are
interpreted cooperatively inside one bounded invocation. No host fork, exec,
pipe or Linux syscall is forwarded. The existing `-p` and legacy profiles retain
their earlier completion boundaries.

## Run

```
compact-linux -j -x /busybox /tmp/busybox ash -c 'echo hi | /busybox cat'
compact-linux -j -x /busybox /tmp/busybox ash -c 'x=$(echo nested | /busybox cat); echo "$x"'
compact-linux -j -x /busybox -x '/probe=/tmp/static-program' /tmp/busybox ash -c '/probe argument | /busybox cat'
```

Each `-x /guest/path` registers the initial ELF under an exact guest execution
path. `-x /guest/path=host-file` instead reads that explicitly named static ELF
into an immutable execution grant. It does not forward subsequent guest paths
to the host. Up to 16 images of at most 4 MiB each are accepted; paths must be
canonical absolute names of at most 255 bytes. Duplicate/reserved resource
bindings are rejected. Granting a name permits execution and synthetic stat
metadata, not arbitrary native file access. Dynamic/PT_INTERP/TLS ELF images and
invalid permissions remain rejected by the shared ELF loader.

`-i` still supplies only a read-only `/input` snapshot and a fresh bounded
write-only `/output` buffer. Successful root exit exports that output. File
resources persist across guest exec and are shared by forked processes; descriptor
access modes continue to apply. Environment variables are explicit; exec sees only
the supplied guest envp. Root and child identities are synthetic guest PIDs, not
native kernel PIDs or remote network identities.

## Process and resource behavior

- fork copies the guest address space and register context. Descriptor tables
  and signal/cwd state are copied; open-file descriptions retain shared offsets
  and status flags. Closing/reusing a descriptor does not retarget its aliases.
- vfork suspends its parent and shares guest memory until successful exec or
  child exit, then resumes the parent. It is not simulated by running a copied
  child to completion. Forking again from the suspended vfork child is rejected.
- Exec snapshots/validates argv and envp before replacing memory. It can select
  a different registered ELF. Invalid paths, images or argument vectors leave
  the existing process intact. Successful exec resets the CPU/TLS bases, preserves
  identity/cwd and signal mask, resets caught dispositions, preserves ignored
  dispositions and closes only descriptors marked close-on-exec.
- wait4 supports child exit status, PID/group selection and WNOHANG. Normal exit
  status uses the Linux wait encoding. Output buffers are prevalidated before
  reaping; rusage is synthetic zero accounting. There are no stopped/continued
  children because asynchronous signal delivery is outside this profile.
- Pipe buffers are 64 KiB rings. Reads/writes block and yield to other guest
  processes; writers resume as readers drain data. Endpoint reference counts
  determine EOF/EPIPE. Nonblocking endpoints return EAGAIN. poll can wait for
  immediate pipe readiness/EOF, without forwarding a host poll call.
- A round-robin scheduler gives each runnable process up to 1024 instructions
  per turn. Blocked syscalls retry with their guest state intact. An entire group
  shares the 262144-instruction/REP budget. A group with no possible progress
  returns explicit deadlock status 8; it never waits indefinitely on the host.
- Limits: 8 process slots including zombies, 32 successful forks, 64 execs,
  16 descriptors per process, 64 shared open-file descriptions, 4 pipes and
  4 MiB aggregate bytes written through pipes. Console output remains 64 KiB
  across the whole group. Each address space is at most 16 MiB. Exec stages a
  replacement arena before committing, so transient allocations exceed the sum
  of the live guest address spaces. These limits are not production isolation
  certification.
- Exiting children close descriptors before becoming waitable zombies. Orphans
  are adopted by the invocation root. Root exit tears down the invocation and
  cancels remaining descendants; it does not create persistent background jobs.

## Verification

`tests/fixtures/compact_jobs.c` is a real static freestanding Linux executable.
The same binary is compared with Linux for private fork memory, shared vfork
memory, exit status, an 81920-byte pipe transfer (larger than one pipe buffer),
and exec/vfork-exec with descriptor close-on-exec and explicit environment.
Additional tests exercise shared file offsets after close/reuse, allocation
failure cleanup, immutable grants, deadlocks, child faults and every group quota.

Unmodified SHA256-pinned BusyBox runs pipelines, nested command substitution and
subshells. A mixed-image pipeline also executes the separately compiled C ELF.
AddressSanitizer and UBSan cover scheduler lifetimes. LeakSanitizer stays enabled
in normal CI. In this restricted local environment its `/proc` thread scan is
unavailable; `COMPACT_DISABLE_LSAN=1` disables that scan explicitly, while address
and undefined-behavior checks stay active. Independent wrapped-allocation tests
check balance after repeated invocations and inject failures at each allocation
on fork/exec paths. Do not label local tests as a successful LeakSanitizer run.

```
python scripts/phase9_shell.py --fetch artifacts/jobs-fixtures
COMPACT_SHELL_DIR=artifacts/jobs-fixtures python -m unittest discover -s tests -p 'test_phase9_jobs.py' -v
```

The mandatory native source-build runner now compiles the process-group runtime
with Plan 9 tools, reboots the source-built kernel and requires a mixed shell
script plus 13 process/resource cases. Checks include executable/script/input
SHA256, source-specific arguments, fork/exec/peak/blocked/pipe-byte counters,
clean exits and every prior kernel, identity and authenticated-resource gate.
Evidence report: `phase9-linux-jobs.json`.

## Remaining Linux compatibility

This completes the bounded process/pipe milestone, not a complete Linux CLI
implementation. General writable files/directories, dynamic linking, development
toolchains, terminal job control, timers, sockets, threads/futexes, general clone
flags and asynchronous signals remain unfinished. SIGPIPE returns EPIPE without
delivering a signal. Background shell `wait` paths relying on sigsuspend/SIGCHLD
handlers are explicitly unsupported; foreground wait4/pipelines are tested.
No Windows/macOS, general x86 ISA or physical hardware qualification is implied.
