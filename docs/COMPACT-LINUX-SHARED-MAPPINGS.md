# Compact Linux shared guest file mappings

The jobs profile supports `mmap(MAP_SHARED)` of regular files in the bounded
writable guest filesystem. Maps refer to the canonical inode, so hardlink aliases,
independent mappings and forked address spaces see the same backing bytes. Guest
file read/write calls observe mapped changes. Closing descriptors or removing all
names does not release a mapped inode. Munmap, successful exec and final address
space teardown release page references; failed exec leaves mappings intact.

There are at most 64 shared file-page bindings per address space. Each is a
4-KiB page with a guest address, inode reference, file offset and permission
ceiling. File bytes remain bounded at 64 KiB and process memory at 16 MiB. Dirty
baselines are allocated on the first shared map, kept off native thread stacks,
and released with the address space. Fork allocates independent mirror/baseline
storage while retaining shared inode references; clone/vfork keep their existing
shared address-space ownership.

## Coherence and syscall buffers

The interpreter refreshes accessed ranges from the inode and commits changed
ranges at instruction and syscall boundaries. Baselines track modified ranges,
so writing one part of a page cannot overwrite another alias's unrelated bytes.
Scalar, vector and repeated-string accesses use the same memory validation path.
Syscall output buffers remain tracked until the operation has finished. Mapped
writes are included in filesystem snapshot output, including changes completed
before a VM step limit is reached.

One deliberately unsupported buffer layout returns EFAULT: a syscall output
buffer (or simultaneously borrowed output buffers) containing distinct virtual
aliases of the same physical file page. This avoids ambiguous deferred copy-out
ordering. Ordinary mapped buffers, readv entries within one mapping and CPU
accesses through aliases are supported. This restriction does not apply to
ordinary overlapping CPU copies; their instruction order determines the result.

## Protection, truncation and faults

Mappings require readable descriptors; shared writable maps require O_RDWR.
Writable shared pages are also readable, matching the AMD64 Linux reference,
even when PROT_READ was not explicitly requested.
Mprotect cannot add write permission to a map created from a read-only descriptor.
Executable mappings of writable guest files and writable/executable pages remain
outside this profile. MAP_FIXED can replace managed mappings after validation;
replaced shared bindings are released. Partial munmap releases only its pages.
Mprotect retains the profile's existing whole-range validation on failure; Linux
may instead have changed an earlier part of a range before returning an error.

The final partial page starts zero-filled beyond EOF. Writes there are visible to
aliases but do not extend the file or enter a saved file's data. File extension
zeroes new bytes. Shrinking clears discarded cached bytes. Access to a page wholly
beyond current EOF raises guest SIGBUS with BUS_ADRERR (2) and si_addr. A handler
may extend the file and return to retry the instruction. Default, blocked and
ignored synchronous SIGBUS terminate the affected process group. Kernel-style
copying to such pages during a syscall returns EFAULT instead. Faulting POP and
POPF preserve their destination register/flags in the saved signal context.

`msync` validates flags/range and completes guest cache synchronization. It does
not promise native disk durability, live host mounts, or crash-atomic snapshots.
Existing private immutable image mappings remain supported. MAP_PRIVATE of
writable guest VFS files, shared anonymous maps, interprocess file-backed futex
keys, remap, locking and huge pages remain unsupported. Non-private futex calls
on file-backed maps explicitly return EOPNOTSUPP; private futex keys retain their
existing address-space behavior.

## Verification

Compiled workloads are compared with Linux for aliases, fork, close/unlink,
partial pages, offsets, fixed replacement, syscall I/O, msync, truncation, SIGBUS
recovery, alternate signal stacks and fault contexts. Policy tests cover read-only
ceilings, mapping quotas, unsupported output aliases and file-backed futexes.
Allocation failure injection covers mapping, fork and exec cleanup; ASan/UBSan
and CI leak checks cover the same paths.

An application linked to checksum-pinned unmodified musl uses pthread atomics,
fork, shared maps and msync. Its mapped file is exported and read in a separate
invocation by unmodified pinned BusyBox. The source-built AMD64 QEMU workflow
requires 27 successful new invocations and an expected step-limit invocation,
including export/reload, fixture SHA256 values and source challenges. Exact results are recorded in
the corresponding PR. This does not establish general Linux application,
operational ARM64 or physical hardware qualification.
