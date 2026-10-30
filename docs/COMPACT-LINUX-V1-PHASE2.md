# CLX-02: root filesystem and resource views

Status: **in progress**. This first increment implements the isolated guest root
profile. It does not complete FS-ROOT, FS-ISOLATION or FS-PERSIST, and does not
qualify the Linux V1 application targets.

## Integration and scope

The user authorized merging on 2026-10-30. PR #76, including the cumulative
previous runtime work, was merged as `bd609ee7c0796ae56f74150553bbd82a05efbf7c`
after all 31 workflows passed on head
`ee45ba9ab466a42e4aecbf5fb6bdfaaf20ce8f3f`. This supersedes the earlier
no-merge instruction for authorized integration; it does not authorize bypassing
checks or publishing kernel binaries. Historical audit records remain unchanged.

| Increment | Result | Remaining acceptance |
| --- | --- | --- |
| 2A | Opt-in guest root, metadata/links, snapshot/restart, early BusyBox file probe | Implemented; exact-head CI/native evidence recorded in the PR |
| 2B | Live filesystem resource mounts with explicit guest destinations, rights, finite quotas and host callbacks | Pending |
| 2C | Shared environment views and narrower per-application grants, inheritance and revocation | Pending |
| 2D | Mount restart/recovery, failure atomicity, complete root/isolation/persistence native acceptance and target blocker report | Pending |

Do not promote a phase because one increment passes. The three phase gates remain
open until 2B–2D pass as well. Continue the frozen application probes throughout;
classify missing filesystem, process, ISA, network and terminal behavior under
the owning phase without substituting target applications.

## First increment

`compact-linux -r ELF [args...]` selects the job runtime with a private writable
root tree. The initial tree contains `/etc`, `/home`, `/usr`, `/var` and `/tmp`,
all owner mode 0700, in addition to `/` mode 0700. Existing owner permission,
umask, directory-fd, rename, hardlink, symlink and bounded file operations apply
across these directories. Fork/exec within a job retains the environment tree;
a new invocation starts empty unless an explicit snapshot is supplied.

`-r` is also supported by the Linux-host differential test harness. The old
configuration value zero and invocations without `-r` keep the historical `/tmp`
profile and snapshot compatibility. `RyzJobConfig.root_tree` accepts only 0 or 1.
No storage, fd, memory or instruction quota was raised: 32 inode/name slots,
64-KiB file data, 16 fds, existing aggregate task/traffic and instruction bounds.
The root and five initial directories occupy six of the 32 slots. These are
bounded development primitives, not sufficient budgets for the V1 toolchain.

`/dev`, `/proc`, `/input`, `/output` and `/compat` remain reserved virtual/resource
paths. A guest pathname never becomes a host pathname; symbolic links cannot
acquire host access. Exact executable/image grants remain immutable and explicit.
Guest-created `/etc/settings` is guest state, not the host's `/etc/settings`.
This root profile has no live mount callback and no per-application narrowing or
revocation yet. Those are separate, necessary 2B/2C work.

## Snapshot boundary

Root snapshots use `FLEXFS4`, with the existing bounded record encoding, metadata,
canonical data and hardlink references, and root record named `root`. Import
requires explicit `-r`. Legacy `FLEXFS1/2/3` requires the historical profile; no
snapshot is silently interpreted with a different root location. No automatic
migration is provided. Reserved root entries, unsupported record types, corrupt
checksums, invalid topology, duplicate identity and path escapes are rejected
before guest execution. Import failure produces no exported replacement.

`-R old-state -W new-state` preserves the existing exclusive-create 0600 output
contract. Reusing an existing output path fails without truncating it. Export is
a completed-operation snapshot, not a journal, authenticated data, fsync durability
or a live host filesystem. Mount recovery and durable storage semantics remain 2D.

## Verification

`tests/test_phase9_rootfs.py` compiles a real freestanding AMD64 Linux ELF. Its
syscalls exercise the five directories, cross-directory hardlinks/symlinks,
permissions, cwd/dirfd/root enumeration, rename, fork sharing, fresh invocation
isolation, independent snapshot reload, reserved path denial and malformed imports.
Address/undefined/leak sanitizer checks run under normal CI. Restricted local
runs explicitly disable unsupported host checks and are diagnostic evidence only.

The pinned unmodified BusyBox 1.35.0 early probe uses ash, mkdir, printf, cp, mv,
ln and cat across `/home`, `/var` and `/usr`. This is a filesystem probe and does
not satisfy APP-BUSYBOX or LOCKS. CPython/Git/GCC/binutils/make execution and source
locks remain pending in their declared phases.

`scripts/phase9_rootfs.py` adds fresh source-built AMD64 QEMU checks. It requires
fixture SHA256s, source-specific challenges, successful create/reload in separate
runtime invocations, the unmodified BusyBox probe and two pre-execution negative
imports. Missing cases, incorrect results, digests or challenges fail qualification.
Native JSON explicitly retains `phase_complete=false` with remaining work. The
inherited kernel and compatibility gates remain required alongside this increment.
