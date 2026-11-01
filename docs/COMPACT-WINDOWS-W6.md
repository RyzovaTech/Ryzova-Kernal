# W6: native integration and qualification gates

This branch adds a Windows-owned Plan 9 portability layer, native mk target,
launcher and native directory-resource transport. It is stacked on W5 PR #87.
Linux/shared runtime and the existing native-build workflows remain unchanged.
W1-W5 hosted comparisons continue as regressions.

## Verified result

[CI run 41266387859](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41266387859)
passed all three jobs: 115 hosted regressions, Windows reference builds/results,
and 19 native QEMU cases. The tested branch head is
`f4ac8d6de71b973280c6bdd8ed1d931fc1242309`; GitHub's tested PR merge commit is
`a93fb0436ede5c099fea6180550f8ee116ede196`.

[The preserved qualification receipt](validation/compact-windows-w6-native.json)
contains source/archive/kernel/runtime/PE hashes, instruction/API counts and
resource results. Native 6c compilation/linking, independent FAT kernel hash
verification, source-built kernel identity, separate ramfs resource operations
and orderly reboot persistence passed. The native file test explicitly took
exit 103 / error 50 at FlushFileBuffers, as expected for the unsupported barrier.
Full W6 remains incomplete under the gates below.

## Evidence workflow

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
The Windows PE exercises create/write/size/seek/read/EOF/close there, plus
case-insensitive reopen and sharing denial before truncation. A stale handle
must fail after close. Distinct roots
must not acquire each other's files. This proves kernel-mediated 9P namespace
resource access, not separate physical/network nodes or distributed performance.

## Next W6 part: acknowledged native flush

The previously preserved receipt below predates this implementation and remains
historical evidence of 19 native cases, including unsupported-flush errors. The
new 22-case run must qualify the isolated `cw-hjfs` durability profile before any
success claim is made for this part.

The Windows-owned hjfs overlay builds a separate binary and uses an explicit
version 1 capability for a dedicated QEMU virtio-SCSI resource disk. The boot
filesystem, original hjfs sources and Linux runtime are unchanged. The barrier
quiesces filesystem operations, drains pending buffer returns, queues dirty writes,
waits for device completion and obtains a non-immediate SCSI SYNCHRONIZE CACHE
GOOD status. Dirty-write failures are sticky. A bounded virtual 9P control fid
returns an ACK only for the current request nonce after all of those steps.
The native provider pins this control fid in the same mounted filesystem as its
explicit grant; generic empty wstat or a command-pipe write never means success.

The native test must run the complete existing MSVC W4 program, require its full
stdout/exit and two acknowledged FlushFileBuffers calls, immediately SIGKILL QEMU,
and recover the exact final W4 bytes from the dedicated filesystem on a fresh
boot without formatting. Background server sync is disabled for this profile. A separate qcow2 overlay
uses QEMU blkdebug to inject one storage-flush EIO after writes. Both that
barrier and the following retry must return error 1117 with zero ACKs; the
second denial checks sticky uncertainty after the one-shot backend fault.
This tests a VM process crash and virtual storage flush semantics, not loss of
physical power or arbitrary hardware storage caches. Unsupported roots retain
error 50. Physical hardware qualification remains a separate outstanding gate.

## Remaining qualification limits

The native qualification report distinguishes:

- AMD64 QEMU execution of the listed bounded cases;
- native 9P namespace I/O and orderly reboot persistence;
- native file flush: new dedicated virtual-storage profile awaiting CI;
- physical hardware: unqualified;
- ARM64 Windows execution: unqualified;
- full W6/general Windows compatibility: incomplete.

The workflow must not mark the full phase/release ready merely because native
subset tests pass. Actual hardware qualification requires identifiable devices,
firmware/drivers, boot/storage/network tests and physical access; this environment
provides no such hardware evidence. The branch remains reviewable without merge.

## Hard-cut scope: boot filesystem versus dedicated acknowledged disk

The native QEMU run [41287084806](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41287084806)
completed the source-built Windows W4 PE with two nonce-acknowledged
\`cw-hjfs\` barriers, then SIGKILLed QEMU. A fresh kernel boot recovered
the exact expected W4 payload SHA-256
\`282108862566a5a16ee67f4282f6c5ae962371e5a393d0001d2bc5883a8961d5\`
from the dedicated /dev/sd01/data resource disk.

The unrelated /tmp/cw-local/payload.bin on the boot hjfs filesystem
was absent after that hard-kill, and boot hjfs reported type mismatches.
The boot filesystem has no acknowledged cw-hjfs SCSI barrier; asserting
its SIGKILL survival as part of the *dedicated resource* barrier was
incorrect. The new hard-cut recovery gate requires an independently
rebooted Ryzova kernel identity, the exact source-built runtime hash,
and the exact dedicated resource file hash. It does NOT claim boot hjfs
crash-safety or physical power-loss durability. The earlier orderly
reboot tests and receipt remain separate historical evidence.

The independent injected QEMU storage error and sticky-error denial
must still pass before native W6's bounded barrier may be qualified.
