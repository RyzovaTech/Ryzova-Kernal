# CLX-03: memory, processes and measured resource profiles

Status: **in progress**. This increment implements **3A private file mappings**.
Its exact-head portable/native results are recorded in the associated PR. It
neither completes MEM-PROC nor supplies RESOURCE measurements. Linux V1 remains
incomplete. Phase 2 is already merged and its inherited acceptance remains required.

## Finite delivery sequence

| Increment | Exit | Current state |
| --- | --- | --- |
| 3A | Mutable-file MAP_PRIVATE/COW, Linux references, failure/lifetime tests, source-built native evidence | Implemented; qualification collected in the PR |
| 3B | Shared anonymous objects and correct shared futex keys/lifetimes, cross-process references and failure tests | Pending |
| 3C | Declared process/session/resource calls required by the frozen application workflows | Pending |
| 3D | Measured per-target image/RAM/steps/time/fd/storage/network budgets and aggregate enforcement | Pending |

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
memory profiles and fork accounting remain 3D work.

Wholly beyond EOF, including a previously detached page after file truncation,
causes the existing guest SIGBUS behavior. Partial-page private tail writes do
not extend the file and remain private across partial truncation/extension, as
checked against Linux. Unmap, fixed replacement, exec and final address-space
release drop inode holds. Dirty private bytes do not enter the shared dirty-page
baseline or persistence path. Shared-only baselines remain lazily allocated;
private-only maps do not allocate that extra 256-KiB mirror.

Non-private futex operations on private file mappings use the existing mm/address
key, matching their private address-space identity. File-backed shared futexes
remain explicitly unsupported until 3B adds real shared keys. Shared anonymous
mappings likewise remain unsupported; no flag is enabled without its backing
object, lifetime and synchronization implementation.

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

No image, arena, task, fd, instruction, filesystem or network ceiling was raised.
All existing root/live-mount isolation and native kernel gates remain mandatory.
Full Linux application compatibility, operational ARM64 and physical hardware
qualification are not outcomes of this increment.
