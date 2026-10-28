# Compact Linux: invocation-local writable filesystem

The opt-in `compact-linux -j` profile now provides writable files and directories
under `/tmp`. Guest code executes through the AMD64 interpreter. Files live in
the invocation's `RyzLinuxWorld`; fork children and replacement images share
this world. Finishing the root invocation releases it. No guest pathname is
forwarded to the host filesystem, and this profile provides no persistent disk.
The old `-p`, file and tiny execution profiles retain their existing boundaries.

Example, with an explicitly supplied static BusyBox ELF:

```sh
compact-linux -j -x /busybox /tmp/busybox ash -c 'mkdir /tmp/demo; echo hello > /tmp/demo/file; /busybox cat /tmp/demo/file'
```

Use `/busybox mkdir` if the selected BusyBox ash does not have standalone applet
lookup enabled. Alternatively grant each required `/bin` applet explicitly.
The native qualification script uses `/busybox APPLET` throughout.

Implemented operations: open/openat including creation, exclusive creation,
read/write and append; shared descriptor offsets; stat/lstat/fstat/fstatat;
seek; mkdir/mkdirat; unlink/unlinkat and rmdir; rename; getdents64;
chdir/fchdir/getcwd; truncate/ftruncate; chmod/fchmod; umask; access;
fsync/fdatasync and utimensat. Sync completes the in-memory operation and does
not promise disk durability. Directory FDs are accepted by openat, fstatat,
mkdirat, unlinkat and utimensat for this virtual filesystem.

Unlinked files remain available through existing open descriptions. Rename
preserves inode identity and open descriptions, including open directory FDs.
Cwd is derived from directory identity, so renaming an ancestor updates getcwd.
Fork shares open descriptions and contents but copies cwd/umask. Exec retains
cwd, umask and non-cloexec descriptions. Executable grants remain immutable;
creating a writable file with a granted executable's name is denied.

Bounds and deliberate limitations:

- 32 inode slots including `/tmp`; each regular file holds at most 65536 bytes.
  Unlinked regular-file slots can be reused once descriptions close. Removed
  directory slots remain reserved until invocation end so cwd references cannot
  accidentally identify a reused directory. Exhaustion returns ENOSPC.
- Existing limits remain: 16 FDs per task, 64 shared descriptions, 8 task slots,
  32 forks, 64 execs, and a shared 262144-instruction/REP budget.
- Paths are at most 255 bytes plus NUL. Dot components, repeated separators,
  trailing separators and parent lookup are checked. A missing or non-directory
  component cannot be bypassed with `..`.
- File ownership is the immutable virtual UID/GID. Owner read/write/search
  permissions and process-local umask are enforced. ACLs, set-ID execution,
  symlinks, hardlinks, mmap of files and additional filesystem mounts are absent.
- Time metadata and realtime/monotonic/boottime clocks use an invocation-local
  logical clock with microsecond ticks. This is not elapsed host or wall time.
  Explicit utimensat values and NOW/OMIT semantics are supported.
- Directory listing is implemented for `/tmp` and its descendants. General root,
  `/dev` and `/proc` directory enumeration remains outside this profile.
- Relative protected-resource paths traversing out of a nested virtual cwd may
  be rejected; use absolute `/input`, `/output` and executable grant names.
- Async signals, background shell wait/SIGCHLD, dynamic linking, threads/futexes,
  sockets, terminal job control and development-toolchain qualification remain
  unfinished. This is not full Linux compatibility or hardware qualification.

Validation includes real freestanding Linux-ABI C programs; Linux differential
checks for file growth/truncation, open-unlink lifetime, shared fork/exec offsets
and utimensat; unmodified pinned BusyBox shell workflows using mkdir/cp/mv/rm,
ls/touch/cat/wc; address/undefined sanitizers; descriptor/inode/byte quotas and
atomic failure checks. CPU additions for these applets (XORPS/XORPD and BSF/BSR)
are compared against hardware for defined results and flags.

Native integration is in `scripts/phase9_vfs.py` and the full native build gate.
It requires a source-built kernel, pinned ELF/script digests, source challenges,
eight C cases and a mixed BusyBox filesystem script. See the validation evidence
for the actual outcome; source code or a Linux-host harness alone is not native
kernel evidence.
