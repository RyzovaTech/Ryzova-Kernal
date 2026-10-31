# W2: import-free Windows AMD64 hosted runtime

W2 adds a separate execution-admission loader and bounded C interpreter under
`ryzova/compat/windows`. It does not modify Linux, the shared CPU, the original
metadata planner, or shared Compact negotiation. W1 PR #83 is an unmerged
prerequisite; this PR is stacked on its branch.

W3 extends this phase baseline with explicit imports and bounded APIs; see
`COMPACT-WINDOWS-W3.md` for the current additional behavior.

## Implemented boundary

`cw_plan` accepts only executable AMD64 PE32+ console images with explicit
section/file alignment, backed executable entry, bounded headers, canonical
64 KiB-aligned image bases, nonoverlapping raw ranges and nonoverlapping mapped
pages. File input is at most 4 MiB. Image plus 64 KiB stack is at most 64 MiB.
Admission failures leave the caller's arena untouched. The host probe allocates
its arena only after successful admission.

The loader copies headers and section bytes, zero-fills the arena/BSS, applies
validated DIR64 relocations and retains final section permissions. Relocation
records must be ordered and nonoverlapping; table self-modification is rejected.
A displaced image without relocation metadata is rejected. Only ABSOLUTE padding
and DIR64 entries are supported. Headers are read-only, code is not writable,
the stack is not executable, and unmapped gaps/guard pages reject access. Guest
addresses never become host instruction pointers. Per-access checks are stricter
than page padding: section-tail padding is inaccessible.

All nonempty data directories except base relocations and bounded, inert debug
metadata are rejected, including imports, delay imports, exception/unwind, TLS,
load config and CLR. Debug records and their payload must be backed and their
RVA/raw file offsets must agree. No PDB, metadata path or external file is opened. This is
a deliberately narrower executable profile than Windows. The old metadata
planner remains unchanged for its research consumers; its acceptance must never
be used to authorize execution. Six W1 audit variants are independently rejected
by the new execution boundary.

The interpreter implements a finite integer/call/stack/move subset plus MOVDQU
and register PXOR for ABI preservation fixtures. Unknown encodings, segment
prefixes, SYSCALL/SYSENTER, privileged instructions and unsupported extensions
stop with an explicit error. The limit is 262144 interpreted instructions; callers
can lower it. The first fault terminates this machine; instruction rollback or
resumption after a fault is not supported. This is not a complete x86 emulator.

## Bootstrap and Windows calling convention

The image entry is called by a synthetic environment bootstrap, with zero
integer arguments, RSP congruent to 8 modulo 16 and 32 bytes of caller-owned
shadow space. There is no red zone. A balanced top-level RET to the trusted,
unmapped return token finishes the environment and preserves the low 32 bits
of RAX as an unsigned DWORD exit code. Jumping to that token does not exit.
This bootstrap supports an import-free `DWORD flex_entry(void)` fixture, not
CRT `main`, WinMain, the NT loader, TEB/PEB or Windows startup libraries.

The probe seeds and checks RBX/RBP/RSI/RDI/R12-R15 and XMM6-XMM15 across entry
return. Independent guest fixtures exercise four register arguments, a fifth
stack argument, stack alignment, all four shadow slots, save/restore, register
widths, flags, branches and nested CALL/RET. Guest functions remain responsible
for following the ABI; the interpreter does not emulate an OS unwinder.

Statuses: 0 success, 1 header, 2 unsupported feature, 3 reserved bounds status,
4 unsafe mapping, 5 relocation, 6 memory access/capacity, 7 opcode,
8 instruction budget, 9 ABI violation detected by the probe.
No API imports or filesystem/network rights are granted in W2. The Python W1
request checker still truthfully reports contract-only: it is not wired to this
standalone execution probe. W3 supplies declared API thunks; W4 supplies handles
and namespace-backed files. The candidate W1 manifest limits are not all runtime
policies yet; W2 enforces the caps explicitly described above.

## Reproduction

```sh
python -m unittest discover -s tests -p test_compact_windows_w2.py -v
python scripts/compact_windows_w2.py
```

Tests use UBSan and an additional deterministic 400-image mutation corpus. They
cover truncation, arithmetic bounds, headers, raw/page overlaps, W+X, entry
backing, data-directory denial, malformed/duplicate/self-targeting relocations,
actual rebased pointer consumption, BSS, permissions, guard pages, stack/ABI,
full DWORD exits, unsupported instructions and instruction exhaustion. This
finite corpus is not exhaustive fuzzing or a security certification.

CI first builds and runs the supplied leaf C source with MSVC on Windows AMD64,
then transfers **that identical executable** and source/executable hash receipt
to Ubuntu. The hosted Flex runtime must independently execute it and match the
actual Windows exit `0x12345678`. No proprietary DLLs or SDK files are copied.
The comparison rejects changed images/sources, wrong checkout/platform and
mismatched results. Native Flex kernel/QEMU execution and physical hardware
qualification are still pending W6; receipts mark this explicitly.

Microsoft references: [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention),
[x64 stack usage](https://learn.microsoft.com/en-us/cpp/build/stack-usage).
