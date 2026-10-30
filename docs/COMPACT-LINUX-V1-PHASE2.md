# CLX-02: root filesystem and resource views

Status: **CLX-02 complete for the declared bounded filesystem profiles**.
FS-ROOT, FS-ISOLATION and FS-PERSIST passed on implementation head
`92904fd4ea8309265cb26ad738fbb62ce72d0eae`: all 30 workflows, 63 Phase 5 +
136 Phase 9 methods without skips, ten plan guards, and fresh source-built AMD64
QEMU root/resource gates. The [acceptance record](validation/compact-linux-v1-phase2-acceptance.json)
contains provenance, artifact IDs and runtime source fingerprints. The final
record/plan revision must also pass CI before integration. Linux V1 and its
application targets remain incomplete; fourteen V1 acceptance IDs remain open.

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
| 2B | Live filesystem resource mounts with explicit guest destinations, rights, finite quotas and host callbacks | Qualified; acceptance record linked above |
| 2C | Shared environment views and narrower per-application grants, inheritance and revocation | Qualified; acceptance record linked above |
| 2D | Mount restart/recovery, failure atomicity, complete root/isolation/persistence native acceptance and target blocker report | Qualified; acceptance record linked above |

The three phase gates closed only after 2B–2D also passed. One increment or a
green baseline alone is insufficient. Continue the frozen application probes; 
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
The completion candidate below adds explicit live mount callbacks and narrower
application views/revocation; the first increment alone did not supply them.

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

## Completion: 2B–2D

The live directory, view/revocation and recovery implementation is qualified
under the profiles below. Future changes must retain the same acceptance gates.

Live directory capabilities use the following launcher interface:

```sh
compact-linux -r -M 'rw:/home/share=/trusted/directory' ELF args...
compact-linux -r -M 'r:/home/share=/trusted/directory' \
  -A '@entry:1:0' -A '/worker:1:0' -x '/worker=/trusted/worker.elf' ELF args...
```

`-M` installs one explicitly selected host/Plan 9 directory at a canonical guest
path. `r` permits lookup/read; `rw` also permits mutation. The core passes only
validated relative paths and guest-buffer slices to trusted, bounded backend
callbacks. POSIX traversal walks open directory descriptors with NOFOLLOW on
every component. Native Plan 9 uses the launcher's private namespace, where
native filesystem walks have no host symbolic-link mechanism. A backend is
trusted code; this API is not a sandbox for arbitrary C callbacks or a promise of
time-bounded access to arbitrary malfunctioning remote filesystem servers.

The mount root and its guest ancestors cannot be renamed/unlinked to bypass the
grant. Host symlinks, special POSIX files, cross-boundary links/renames, mounted
executable loading and mmap are denied. Managed-root symlinks may refer into a
mount, but lookup still checks the current view and revocation state. Virtual
root operations and exact immutable ELF grants retain their previous behavior.

Views use mount-index bitmasks, starting at bit 0 in `-M` order. `-A` associates
read/write masks with a canonical executable grant; `@entry` selects the initial
application. Write bits must be a subset of read bits. Fork/threads inherit the
caller's view. Successful exec intersects the existing view with its declared
policy; re-exec through a more privileged alias cannot restore removed rights.
The optional Flex extension `prctl(0x46534e53, read_mask, write_mask, 0, 0)` only
narrows the calling task's view. This is a documented Flex extension, not an
upstream Linux prctl option. Threads within one application share memory and may
intentionally cooperate; narrower views do not isolate mutually hostile threads.
The managed environment root remains shared; views narrow external filesystem
capabilities. Network grants receive their separate acceptance in CLX-05.

`-K /trusted/control` opens an administrator-selected control file. A first byte
`1` permits the configured grants. Any other content/read failure revokes a mount
on its next access, permanently for that invocation. Checks include already-open
fds, readv/writev, positioned I/O, stat, seek, cwd, dirfd and enumeration. Close
still releases the backend handle after revocation. Revocation denies future I/O;
it does not erase data already copied into guest memory. The control descriptor is
never implicitly mapped into the guest. The qualification fixture explicitly
grants a separate admin capability solely to exercise the real revoke path.

### Bounded filesystem profiles

| Behavior | Managed guest root | Linux-host directory reference | Native Plan 9 directory |
| --- | --- | --- | --- |
| Directory/file operations, metadata, bounded I/O | Existing guest model | Live host operations | Live native/9P operations |
| Rename within/across guest directories | Existing atomic guest operation | Host renameat | Same-directory, absent destination only |
| Existing-destination rename | Existing replacement rules | Host atomic replacement | EEXIST; existing data preserved |
| Cross-directory native rename | Guest model | Supported | EXDEV; existing data preserved |
| Hard/symbolic links | Existing guest model | Deliberately denied across resource interface | Denied |
| File-backed mmap | Existing bounded guest-file support | Denied for resource fds | Denied for resource fds |
| fsync durability | Snapshot boundary, not power-loss proof | Real host fsync | EOPNOTSUPP; no false durability acknowledgement |

A native 9P directory is not advertised as a general POSIX filesystem. Projects
requiring guest hardlinks or replacement rename use the managed root. A future
application requirement that needs additional filesystem semantics reopens the
owning filesystem gate; it must not silently be relabeled as a CPU/network fix.
Directory fds/cwd cache their canonical guest name. Relative operations follow
the currently authorized name; a concurrent external rename can invalidate it.
This profile does not claim Linux's renamed-directory-handle semantics or concurrent
multiwriter append atomicity. These limitations do not change the V1 target
versions or promote any application workflow to passed.

Limits: four mount capabilities, sixteen per-executable policies, the existing
sixteen guest fds/sixty-four descriptions, 64-KiB regular files, 32 enumerated
children per directory, 32 successful resource creations per invocation, 4-MiB
aggregate file data transfer and 65,536 backend calls. Existing instruction/task
limits remain enforced. Metadata enumeration is separately bounded by the call
and directory-entry limits. Backend handles close once on last-description
release, including fork/dup/exec, fault and revocation paths.

### Persistence and recovery

Writes are live: a second capability/node sees the same backend data, and a new
runtime invocation reads it without a snapshot import. A guest step-limit fault
retains completed backend writes; it cannot roll back or claim uncompleted writes.
Callback failures and impossible reply lengths return errno without advancing
file offsets or reported transfer counts. Rejected oversized truncating opens,
creation quota exhaustion and native rename failures preserve existing files.

FLEXFS4 exports only managed guest state and inert mount-point directories. It
contains no external file contents, host path, native handle, view or revocation
credential. Reload without an explicit mount grants no backend access. Recovery
requires explicit reattachment to the same selected directory; a readonly
reattachment remains readonly. This proves restart/completed-operation recovery,
not filesystem journaling or physical power-loss durability. Existing exclusive
snapshot-output creation and corruption/topology checks remain required.

### Target probes and remaining owners

| Frozen target | CLX-02 result | Remaining owner |
| --- | --- | --- |
| BusyBox 1.35.0 | Unmodified ash/mkdir/printf/cp/mv/cat on managed root and live mount; actual source file persists | Full applets, PTY/jobs and locks: CLX-06/07 |
| musl 1.2.6 | Inherited dynamic-loader/thread regressions remain required | Developer footprint/API and final workload budgets: CLX-03/04/07 |
| CPython 3.12.10 | Named target has no locked runnable fixture; not qualified | Build locks and actual binary/ISA/process probes: CLX-03/04/07 |
| Git 2.49.0 | Named target has no locked runnable fixture; native live-mount rename limitations explicit | Managed-root workflow/locks: CLX-07; HTTPS: CLX-05 |
| GCC 14.2.0, binutils 2.43.1, make 4.4.1 | Named targets have no locked runnable fixtures; TinyCC is not substituted | Memory/ISA: CLX-03/04; actual toolchain/locks: CLX-07 |

`tests/test_phase9_mounts.py` and its C fixtures exercise real backend changes,
restart without export, separate-node aliases, view inheritance/re-exec,
revocation of open fds, hidden enumeration, host traversal/link denial, finite
quotas, low-fd-limit handle lifetimes, sanitizers and callback fault injection.
`scripts/phase9_mounts.py` adds mandatory source-built QEMU challenges, host-data
comparison, independent restart/reattach, negative rights/revocation, guest-fault
recovery and the pinned BusyBox probe. Its evidence must pass alongside the prior
root-tree gate and all inherited native checks. Linux V1 remains incomplete.
