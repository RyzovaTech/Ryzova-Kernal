# Compact Linux: selected unmodified BusyBox applets

The `compact-linux -p` native user-space application now interprets the pinned,
unmodified `busybox_TRUE`, `busybox_ECHO` and `busybox_PRINTF` static AMD64
executables published at:
https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/

These historical third-party executables are compatibility fixtures. This does
not package a current Linux distribution or establish general musl/libc support.
No third-party binaries are committed. The helper verifies SHA256 before execution;
URLs and digests are in `scripts/phase9_busybox.py`.

## Run and reproduce

```
python scripts/phase9_busybox.py --fetch artifacts/busybox-fixtures
COMPACT_BUSYBOX_DIR=artifacts/busybox-fixtures python -m unittest discover -s tests -p 'test_phase9*.py' -v
```

Inside the native guest, after transferring the verified files:

```
compact-linux -p /tmp/bb-true
compact-linux -p /tmp/bb-echo hello
compact-linux -p /tmp/bb-printf '%d %x\n' 123 255
```

The shell shown here is the native host shell. It is not a Linux guest shell.
The mandatory source-build workflow compiles the interpreter with Plan 9 tools,
boots the source-built kernel in a fresh QEMU instance, checks the downloaded
ELF digests inside that guest, runs all three commands and requires successful
interpreter exits, exact printf output and a commit-specific echo challenge.
`phase9-linux-busybox.json` preserves those individual checks. Host-only tests
never count as native evidence.

## Runtime changes

The opt-in process profile accepts a 4 MiB ELF image and a bounded 16 MiB arena.
Its instruction/REP-iteration budget remains 262144. Legacy profiles retain
1 MiB image / 2 MiB arena limits. New interpreted operations include ADC/SBB,
low-word signed multiplication, signed/unsigned division with explicit arithmetic
faults, bit-test operations, byte shifts, guarded REP MOVS/STOS and 16-byte vector
copies. Floating-point/vector arithmetic and the rest of the AMD64 ISA remain
unsupported. Repeated memory operations consume the same bounded execution budget.

`arch_prctl` exposes virtual FS/GS bases only inside guest memory;
`set_tid_address` records a guest pointer and clears it on normal exit. Neither
creates host TLS or a guest thread. `writev` validates at most 16 guest iovecs and
64 KiB total; buffers and descriptors remain virtual. Limited `fcntl` exposes
virtual descriptor flags and `ioctl` returns ENOTTY for these non-terminal files.
No Linux syscall is forwarded to the native host.

## Completion boundary

The subsequent bounded shell profile removes the stat-startup blocker for the
pinned multicall binary and qualifies selected ash scripts. See
[COMPACT-LINUX-SHELL.md](COMPACT-LINUX-SHELL.md). The following describes this
earlier standalone-applet milestone.


This qualifies three selected standalone applets and the pre-existing custom
compiled-C/file workloads. The full multi-call BusyBox executable currently stops
at an unsupported stat-family syscall. BusyBox ash, arbitrary shell scripts,
fork/exec/wait, pipes, directories/stat, signals, threads/futexes, dynamic ELF,
general application libc/TLS, development toolchains, GUI, sockets and physical
hardware qualification remain unfinished. The requested complete CLI environment
is therefore **not complete** at this milestone. Windows/macOS environments are
also not implemented by this change.
