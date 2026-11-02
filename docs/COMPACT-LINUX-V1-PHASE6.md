<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# CLX-06 research — Bounded raw PTY master/slave

This is an **increment**, NOT CLX-06 TTY-JOBS qualification. The optional
user-space Compact Linux world provides up to two virtual raw PTY pairs.
`/dev/ptmx` issues a namespace-owned master and grants its slave only
after the `TIOCSPTLCK` unlock operation. `TIOCGPTN` returns a bounded
instance number, and `/dev/pts/0` or `/dev/pts/1` can be opened only
with matching namespace ID and UID while an owner master is live.
Read/write use two separate 4096-byte bounded ring buffers with a 4 MiB
per-world cumulative transfer quota, no host FD access and no untrusted
external network/device bridging. Close/reopen resets state after the
last shared master/slave description reference disappears.

Supported ioctls for this research: TIOCGPTN, TIOCSPTLCK, TIOCGWINSZ,
TIOCSWINSZ (no SIGWINCH), TCGETS and TCSETS **raw-only**. Canonical mode,
echo, VMIN/VTIME completeness, foreground/background job groups,
SIGTSTP/SIGWINCH, /proc/devpts integration, full termios and real kernel
PTY attachment are **not** provided. Unsupported modes reject explicitly.
A source-built AMD64 guest test executable performs real open/unlock,
termios raw setup, winsize read/write, master-to-slave and slave-to-master
byte transfers and compares its output with actual host Linux. Negative
guest tests reject unauthorized locked slave access and malformed ioctls.

The TTY-JOBS acceptance gate remains pending. Even passing Python host
tests and a native QEMU regression suite does not prove an unmodified
BusyBox ash interactive PTY session in the Ryzova native kernel.

An additional source-built C harness attaches three guest process states to
one finite Ryzova world. It verifies that a locked slave cannot open, and
that a different namespace ID or UID cannot open the owner's slave even
when it is unlocked; after the last descriptor closes, authorization is not
retained. This is a **hosted VM isolation test**, not a real kernel multi-user
or native Ryzova /dev/pts implementation.

The raw PTY fixture additionally checks guest `stat`/`fstat` character-device
metadata against real Linux, while the shared-world cross-namespace harness
requires `stat('/dev/pts/0')` to return `ENOENT` for unauthorized nodes.
Per-slot inode metadata is bounded and cannot escape the caller's namespace.
This does not implement the full `/dev/pts` directory or dynamic devpts
mount semantics, canonical line discipline, or interactive shell process-group
control.
