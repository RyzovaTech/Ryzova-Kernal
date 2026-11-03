# Compact Linux bounded shell profile

The opt-in native user-space Compact application can run the unmodified, pinned
BusyBox 1.35.0 AMD64 static multicall ELF, including selected ash shell workloads.
The source-built Ryzova kernel hosts the interpreter; this does not boot a Linux
kernel or forward guest Linux syscalls to the host.

## Reproduce

```
python scripts/phase9_busybox.py --fetch artifacts/busybox-fixtures
python scripts/phase9_shell.py --fetch artifacts/shell-fixtures
COMPACT_BUSYBOX_DIR=artifacts/busybox-fixtures COMPACT_SHELL_DIR=artifacts/shell-fixtures python -m unittest discover -s tests -p 'test_phase9*.py' -v
```

The same SHA256-pinned multicall ELF runs both on Linux and through Compact in
host differential tests. These historical binaries are compatibility test fixtures,
not a current recommended distribution. None are committed or shipped as artifacts.
The fixture URL/hash is in `scripts/phase9_shell.py`.

Inside the native guest, transfer the verified executable and grant input explicitly:

```
compact-linux -p /tmp/busybox ash -c 'echo hello'
compact-linux -p -i /path/to/script /tmp/busybox ash /input argument
compact-linux -p -i /path/to/data /tmp/busybox cat /input
compact-linux -p -i /path/to/data /tmp/busybox wc -c /input
compact-linux -p -i /path/to/data /tmp/busybox ash -c 'read x </input; echo "$x"'
compact-linux -p -i /path/to/data /tmp/busybox ash -c 'echo first >/output; echo second >>/output'
```

`/input` is a read-only snapshot of the single explicitly granted file. `/output`
is a fresh, bounded write-only export buffer. Successful process exit exports its
contents to the native caller's stdout. Script execution and file access do not
grant access to the caller's host namespace. The read-only native discovery
service now includes `/compact/linux/shell` with these limitations.

## Qualified behavior

Tests cover variables, explicit environment, Unicode, arithmetic expansion,
loops, functions, conditionals/case, an input script with a source-specific
argument challenge, shell input/output redirection, truncate/append, and multicall
cat/wc. These are finite, noninteractive workloads. A 262144 instruction/REP
budget still applies to the entire invocation; an infinite loop fails at that
budget. Memory stays inside a 16 MiB arena, image input is capped at 4 MiB,
file and console buffers at 64 KiB, and descriptors at 16.

The native source-build workflow now requires five successful guest invocations:
script, cat with byte-for-byte comparison, wc byte count, read redirection and
output append. It checks executable/script/data digests in the guest, exact
console output, a commit-specific argument, clean process exits and all previous
kernel/resource/identity checks. Evidence: `phase9-linux-shell.json`.

## Virtual resource behavior

- stat/fstat/lstat and restricted fstatat serialize the 144-byte AMD64 Linux UAPI
  layout. Mode, synthetic identity, file size and device properties derive only
  from granted guest resources. Timestamps and padding are zero. No host metadata
  is exposed. Missing paths, including `/etc/busybox.conf`, return ENOENT.
- open/openat, lseek, dup/dup2/dup3 and limited fcntl operate on guest descriptors.
  Duplicate descriptors share offsets and append state while retaining individual
  close-on-exec flags. Closing/reusing the original descriptor does not retarget
  its aliases. O_CREAT applies only to the already granted output resource;
  arbitrary file/directory creation is unsupported.
- cwd navigation is restricted to `/` and `/tmp`; paths cannot traverse outside
  the virtual namespace. Root/tmp metadata is synthetic. `/proc/self` metadata
  does not provide a general navigable procfs.
- uname describes the virtual Linux ABI environment (`flex-abi-0.1`, x86_64),
  not the actual host OS. UID/GID remain fixed guest identities; requests to
  change them to another identity return EPERM.
- rt_sigaction/rt_sigprocmask store/query guest state only. No asynchronous
  signals are generated or delivered; signal return/kill/thread semantics are
  unsupported. Recording a handler does not execute it. SIGKILL/SIGSTOP cannot
  be masked or installed as handlers.
- poll reports immediate readiness only for bounded buffers and virtual stdio.
  Unsupported waiting with no ready descriptors returns ENOSYS. sendfile also
  returns ENOSYS, allowing normal read/write fallback. Neither reaches the host.
- Additional interpreted CPU operations are byte INC/DEC, guarded PXOR and
  aligned vector copies, memory LOCK OR and CMPXCHG. The interpreter is single
  threaded; these do not establish guest thread or general atomic-ISA support.

## Completion boundary

The subsequent opt-in `-j` profile implements bounded fork/vfork, registered-image
exec, wait4 and pipes; see [COMPACT-LINUX-JOBS.md](COMPACT-LINUX-JOBS.md). The
limitations below describe this earlier single-process `-p` profile.


This is a usable **bounded shell subset**, not a complete Linux CLI environment.
Pipelines, command substitution, fork/exec/wait, subprocess scheduling and pipes
are not implemented. Scripts requiring them fail explicitly. Dynamic ELF,
application toolchains, general file/directory creation, sockets, timers, terminal
job control, asynchronous signals, threads/futexes and broad application/physical
hardware qualification remain unfinished. General Linux completion must not be
inferred from successful shell builtins or these five native workloads.

## Recorded validation

[Local native evidence](validation/phase9-6-local-native.json) records the tested
remote commit, the separate local validation snapshot, matching Git hashes for
all six kernel/header/runtime/script/test source subtrees, the independently
extracted kernel hash and each mandatory native report. The local snapshot
omits unrelated repository subtrees and is not a GitHub PR merge commit.

All five native shell/file workloads passed on the source-built kernel. All 29
Phase 9 tests, 63 Phase 5 tests, 4 M2 evidence tests and 5 M4 legacy gate tests
passed locally. GitHub Actions jobs stopped before runner allocation, including
a retry; the connector did not expose the underlying reason. Local QEMU success
must not be presented as successful GitHub Actions checks.

For environments that prohibit Unix control sockets, set
`RYZOVA_QEMU_LOOPBACK=1` when running `scripts/phase3-native-build.py`. QEMU serial
and monitor control channels then bind only to 127.0.0.1 on ephemeral ports.
Guest networking, TLS, identity and resource validation remain mandatory. The
normal CI Unix-socket transport remains the default.
