# CLX-03: memory, processes and measured resource profiles

Status: **in progress**. 3A is merged; the next increment implements **3B shared backing/futex**, the
declared **3C session/resource API profile**, and **3D aggregate arena enforcement**.
Its exact-head portable/native results are recorded in the associated PR. It
neither completes MEM-PROC nor supplies RESOURCE measurements. Linux V1 remains
incomplete. Phase 2 is already merged and its inherited acceptance remains required.

## Finite delivery sequence

| Increment | Exit | Current state |
| --- | --- | --- |
| 3A | Mutable-file MAP_PRIVATE/COW, Linux references, failure/lifetime tests, source-built native evidence | Implemented; qualification collected in the PR |
| 3B | Shared anonymous objects and correct shared futex keys/lifetimes, cross-process references and failure tests | Implemented; exact-head qualification in associated PR |
| 3C | Declared process/session/resource calls required by the frozen application workflows | Declared bounded API profile implemented; wider target discovery remains open |
| 3D | Measured per-target image/RAM/steps/time/fd/storage/network budgets and aggregate enforcement | Arena enforcement/measurements implemented; named-target measurements blocked |

The phase closes only after MEM-PROC and RESOURCE both have evidence. A larger
test count or passing 3A alone does not close those gates. Versioned BusyBox,
CPython, Git, GCC/binutils/Make and musl target versions remain unchanged. Missing
locked runnable target fixtures must be recorded as blockers to measurements;
substituting TinyCC for GCC or invented footprint estimates is not acceptance.

## Private file COW model

Managed guest regular files support MAP_PRIVATE alongside existing MAP_SHARED.
The binding retains the file inode after fd close/unlink, tracks its file offset,
and enforces the same sparse 64-page binding budget per address space. The first
write copies the entire 4-KiB backing page into the guest's private arena and
marks it detached. Subsequent writes/read-modify-write instructions and syscall
output buffers use that detached page. Private changes never update the file,
shared aliases, timestamps, msync output or exported filesystem snapshots.

A private writable mapping may be made through a readable readonly fd; mprotect
can add write access to that private mapping. Shared writable mappings retain
their O_RDWR restriction. Mutable-file executable mappings and W+X remain denied.
Resource-capability fds are still not mappable; their revocation contract is not
bypassed. Immutable executable/library grants keep their existing loader behavior.

The first private write copies the whole page, including bytes not touched by
that write. Later file writes do not replace those bytes. Clean private pages
currently refresh from the guest file cache; Linux does not guarantee a portable
visibility contract for every concurrent file change to a MAP_PRIVATE mapping.
No application requirement is based on that unspecified behavior. Tests instead
check stable first-write isolation, separate pages, mixed private/shared views,
readonly fds, syscall output and backing-file persistence.

Fork keeps private contents isolated in parent and child. The current process
implementation still eagerly copies the bounded arena on fork; this increment
implements **file-page copy on first write**, not a claim of physically shared
fork pages, demand paging or reduced aggregate fork RAM. Shared threads retain
the same address space and therefore its private mappings. Aggregate developer
memory profiles remain 3D work; arena reservations are now accounted and capped.

Wholly beyond EOF, including a previously detached page after file truncation,
causes the existing guest SIGBUS behavior. Partial-page private tail writes do
not extend the file and remain private across partial truncation/extension, as
checked against Linux. Unmap, fixed replacement, exec and final address-space
release drop inode holds. Dirty private bytes do not enter the shared dirty-page
baseline or persistence path. Shared-only baselines remain lazily allocated;
private-only maps do not allocate that extra 256-KiB mirror.

## Shared backing objects and futex lifetimes

MAP_SHARED|MAP_ANONYMOUS now allocates zeroed 4-KiB backing objects in a fixed
64-page pool per environment. Fork retains the same objects; private anonymous
maps remain isolated. These bindings share the existing 64-binding per-MM quota
with file mappings. Unmap, fixed replacement, brk shrink, exec, signal/timeout
cleanup and final job teardown release holds. Recycled slots receive monotonic
identities, so a freed/reused slot cannot accidentally match an old waiter.
The pool occupies a fixed additional 256 KiB inside the bounded world object.

Shared anonymous futex keys use backing identity plus page offset. Shared managed
file keys use inode identity plus file offset, so different virtual addresses and
forked processes can synchronize. Private futexes use MM/address identity.
WAIT/WAKE, bitmasks, CMP_REQUEUE/REQUEUE and logical timeouts retain keys while
queued; requeue transfers the hold. Unmapping the original VA does not cancel
or dereference that queued address. A queued key prevents premature backing
reclamation and inode reuse. PI futexes remain unsupported.

## Declared process/session and resource APIs

The job profile implements setpgid/getpgid, setsid/getsid, getrlimit/setrlimit and
prlimit64. Groups/sessions are namespace-local, inherited across fork/exec and
consistent across threads. Child/session/group-leader restrictions and the
post-exec parent setpgid denial are enforced. This is the declared profile,
not a claim that all process APIs needed by unbuilt targets have been discovered.

NOFILE defaults to soft/hard 16 and gates new managed/live/socket/pipe/dup fds;
existing descriptors still work after lowering. NPROC defaults to 8 and gates
fork/clone against occupied namespace task slots (including unreaped zombies),
rather than the host UID's process count. AS defaults to 16 MiB and gates mapped
pages, brk growth and replacement images. Fork/exec inherit limits; updates are
shared by a thread group. Soft limits may be raised to the current hard limit;
hard limits may only be lowered. STACK=64 KiB and CORE=0 may be queried; changes
outside those fixed supported values fail explicitly. Other resource classes
return EINVAL. prlimit follows Linux's update-before-old-value-copyout behavior:
a bad output pointer can report EFAULT after an otherwise valid update.

## Aggregate arena budget and measurement boundary

`-j -B bytes` configures a job-wide arena reservation ceiling, capped at
150,994,944 bytes (nine 16-MiB arenas). The default is the same finite ceiling.
It counts the initial arena, owned fork copies, and the temporary replacement
arena before exec releases the old one. Admission happens before allocation;
failed fork/exec leaves the caller intact. Shared-mm clone/vfork does not charge
a second arena. `COMPACT_RESOURCE_STATS` reports measured arena reservation peak
and shared backing-page peak. These are not total process RSS measurements:
image buffers, world/task metadata, lazy file mirrors, I/O buffers, native kernel
memory and the host runner remain distinct allocations with existing finite caps.

A one-arena test proves both fork and staged exec reject at the cap while the
caller/shared bytes survive. The native gate records actual peaks for each of
22 fixture workflows. None is a substitute for measurements of the seven frozen
application targets. CPython 3.12.10, Git 2.49.0, GCC 14.2.0, binutils 2.43.1 and
Make 4.4.1 have no locked runnable guest artifacts yet; their transitive libraries
and workload locks remain needed. Existing BusyBox/musl/TinyCC regression results
are retained, but they do not qualify all RESOURCE dimensions or GCC.

## Evidence and limits

`tests/test_phase9_private_maps.py` compiles a real freestanding AMD64 Linux ELF.
Fifteen workflows compare actual guest and Linux execution: private/backing-file
isolation, readonly fd/protection transitions, dirty/clean fork, page granularity,
offset, private/shared coexistence, syscall output, unlink/recycling, truncation
SIGBUS, private tail bytes, fixed replacement, futex policy and exec cleanup.
The artificial environment's finite binding quota is tested separately, since
Linux has no identical 64-binding limit. Snapshot reload proves that private
changes were not persisted. Allocation failures, address/undefined/leak checks
and old shared-map regressions remain required.

`scripts/phase9_private_maps.py` adds eighteen positive native invocations on a
fresh source-built AMD64 QEMU guest, fixture SHA256, source-specific challenges,
independent save/reload and exact clean-result counts. The native driver advances
past the prior mount gate to the new final marker. Missing cases or substituted
logs fail the gate. Its evidence explicitly reports phase_complete=false and
lists 3B–3D as remaining work.

No per-process image, arena, task, fd, instruction, filesystem or network ceiling was raised.
The new aggregate arena ceiling includes exec staging and is explicit above.
All existing root/live-mount isolation and native kernel gates remain mandatory.
Full Linux application compatibility, operational ARM64 and physical hardware
qualification are not outcomes of this increment.

`tests/test_phase9_process_resources.py` adds Linux differential references,
shared-key pool pin/recycle checks, allocation-failure balance and sanitizers.
`scripts/phase9_process_resources.py` extends the source-built native chain with
22 invocations, unique markers, fixture digest, source challenges, exact clean
result counts and measured arena peaks. The driver only exits on the new final
marker; old runtime markers cannot terminate it early. Missing/mutated evidence
fails. MEM-PROC remains partial until its declared profile is qualified and wider
required-call scope is resolved; RESOURCE and Phase 3 remain open.
