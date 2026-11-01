# W6: native integration and qualification gates

This branch adds a Windows-owned Plan 9 portability layer, native mk target,
launcher and native directory-resource transport. It is stacked on W5 PR #87.
Linux/shared runtime and the existing native-build workflows remain unchanged.
W1-W5 hosted comparisons continue as regressions.

## Evidence to collect

The new workflow compiles the existing Windows reference programs with MSVC,
verifies their native results and transfers only project fixture binaries and
hash receipts. Four additional compiler-built PE probes exercise Flex-specific
heap/output/handle quotas and ordinary I/O on a separate ramfs 9P server. Those
resource probes are compiled on Windows but intentionally not run as Windows
conformance examples: their limits belong to the Flex profile.

A disposable pinned 9front build VM receives the exact source archive. Its native
6c/mk builds compact-windows and a fresh Ryzova AMD64 kernel. Built/installed FAT
kernel SHA256 values must match; a host extraction independently checks the FAT
bootfile hash. A new QEMU process boots that source-built kernel, checks #Z
identity and native runtime SHA, then executes the identical PE files. A third
boot checks file persistence after an orderly filesystem sync. No upstream boot,
Linux GCC test or serial command echo is accepted as native runtime evidence.

Native cases cover all six W5 workloads, W3 APIs, W4 file behavior, explicit
read-only/no-flush grants, 1 MiB private heap exhaustion, 64 KiB I/O denial,
30 file handle slots, 1024-step exhaustion, stack guard access, oversize image/file
admission and missing API permissions. Native reports include interpreted steps,
explicit launch-buffer request totals, guest arena/heap bytes, current committed
heap bytes and observed peak native file handles. These are scoped accounting
measurements, not total RSS or a claim to count libc/server allocations.

## Native resource semantics

The native launcher creates a private RFNAMEG/RFENVG view and attaches one explicit
C drive root, with the same copied directory rights as W4. File access uses the
portable CwFileOps interface, native qid/device/type identity and directory scans.
It rejects cross-device descendants and nonordinary qid types, checks sharing
before truncation and pins open descriptors. Paths retain the bounded ASCII
profile. The provider trusts the native launcher and owning 9P server; it does
not defend against a malicious native administrator replacing namespace objects.

The second namespace in the QEMU test is a separate native ramfs 9P server process.
The Windows PE performs actual create/write/close/reopen/read there. Distinct roots
must not acquire each other's files. This proves kernel-mediated 9P namespace
resource access, not separate physical/network nodes or distributed performance.

## Flush is deliberately a remaining gate

A native FlushFileBuffers success is **not implemented**. Generic 9P empty wstat
has optional synchronization semantics. The pinned hjfs control interface accepts
commands through a pipe, so writing `sync` is not an acknowledgement that stable
storage has completed. Returning success from either operation without a verified
barrier would misrepresent the Windows API contract.

The native provider returns error 50 for FlushFileBuffers. Consequently the W4
reference is expected to take its error-handling exit 103 in native QEMU, while
its full success/persistent-byte comparison remains qualified on the hosted Linux
fsync transport. Native tests explicitly require error 50 rather than hiding it.
Read/write/seek/close/rights and separate 9P resource I/O can still be qualified.
A future acknowledged server durability capability is required before clearing
the full native file-profile gate. Passing orderly reboot persistence is useful
but is not a replacement for that barrier or a power-loss test.

## Remaining qualification limits

The native qualification report distinguishes:

- AMD64 QEMU execution of the listed bounded cases;
- native 9P namespace I/O and orderly reboot persistence;
- native file flush: unqualified;
- physical hardware: unqualified;
- ARM64 Windows execution: unqualified;
- full W6/general Windows compatibility: incomplete.

The workflow must not mark the full phase/release ready merely because native
subset tests pass. Actual hardware qualification requires identifiable devices,
firmware/drivers, boot/storage/network tests and physical access; this environment
provides no such hardware evidence. The branch remains reviewable without merge.
