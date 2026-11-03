<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Compact macOS — MAC-0 foundation and security contract

**Status: restricted Intel Mach-O metadata foundation; NOT macOS application execution.**

## Source baseline / ownership

This effort starts from the existing `ryzova/compat/macos/macho64.c` and
`macho64.h` implementation (Phase 5.7). It is a host-side, read-only
**metadata validator**, *not* a Mach-O loader, a native guest service, a
Darwin/Mach syscall translator or a kernel-mounted `/mac` namespace.

MAC-0 changes stay in `ryzova/compat/macos`, Mac-only tests/scripts/docs and
Mac-only CI. Linux and Windows application runtime branches, native kernel
drivers and the separate driver agent remain outside this scope. Automatic
9front synchronization stays disabled.

The frozen contract lives in
`ryzova/compat/macos/mac0-contract.json`; the inventory script
`scripts/compact_macos_m0_audit.py` emits a SHA-256 evidence JSON for the
actual sources and documents. The script rejects forged capabilities or
implicit host authority; an audit PASS is **not proof of native guest boot**.

## MAC-0 bounded parser policy

The initial **AMD64 x86_64 CPU_SUBTYPE_X86_64_ALL** research profile only
accepts `MH_EXECUTE` non-PIE Mach-O 64-bit with one `LC_MAIN`. At most
32 commands, 16 segments, 4 MiB host-probe input, and 64 MiB per segment.
All mappings must stay strictly within the lower canonical user half with
address at least 64 KiB. The planner rejects overlapping VM segments,
writable+executable protections, file ranges outside input and ambiguous
executable entrypoint mappings.

Only narrowly validated `LC_SEGMENT_64`, `LC_MAIN`, `LC_UUID`,
`LC_BUILD_VERSION` (macOS platform 1) and `LC_VERSION_MIN_MACOSX` metadata
commands are admissible. Each must have an exact bounded payload size, and
the two version forms are not accepted together. `section_64` metadata
is bounded, attached to its enclosing segment, and cannot claim an invalid
file-backed span, overflow or relocations. Encrypted images, code signing,
dyld/chained fixups, libraries, thread-state execution, PIE, SDK-based
frameworks and Apple Silicon are not accepted as runnable workloads.

A parser's acceptance means only that the bounded *metadata shape* was
admitted. The returned entry is an **untrusted unsigned integer** until
a separate authenticated launcher, memory-permission manager and native
runtime qualification exists. Never jump to that entry from this parser.

## MAC-0 mandatory verification

1. GCC and Clang, strict C11 warning and UBSan host-side tests.
2. Existing Phase 5.7 positive and negative Mach-O fixture tests.
3. Additional MAC-0 negative cases: wrong subtype, upper-half canonical
   addresses, overflow, malformed UUID/build/version commands, invalid
   `section_64` backing/alignment, duplicate/ambiguous entry and bounded
   deterministic mutations (synthetic input only).
4. Freestanding compilation of the parser with GCC and Clang.
5. Contract-falsification and provenance tests; artifact includes hashes
   and explicitly false native/execution/release fields.
6. Exact-head existing native AMD64 source-built QEMU/driver/security
   regressions must remain green before any integration into `main`.

## Planned subsequent phases (same final integration branch)

| Phase | Planned gate, not implemented by MAC-0 |
| --- | --- |
| MAC-1 | Bounded, original Ryzova Mach-O AMD64 load/entry execution with memory/W^X tests |
| MAC-2 | Clearly scoped Darwin ABI and Mach-message service, isolation and negative tests |
| MAC-3 | `libSystem` and dyld/linking research using lawful, pinned open-source fixtures |
| MAC-4 | Namespace-backed POSIX filesystem, process permissions and per-session handles |
| MAC-5 | Selective Objective-C/Foundation compatibility research, GUI excluded until separately accepted |
| MAC-6 | Pinned macOS command-line reference fixtures and Ryzova guest differential evidence |
| MAC-7 | Native source-built QEMU acceptance, fault recovery, license/release review |

**No Apple-proprietary SDK binaries, system frameworks or macOS images are
copied into the repository.** Apple public-source Mach-O headers and loader
documentation may be consulted for structure layouts, but this is a
separately implemented Ryzova validator (AGPL-3.0-only).

References (format contracts, not proof of compatibility):

- Apple XNU `EXTERNAL_HEADERS/mach-o/loader.h` (public source)
- Apple dyld `mach_o/UnsafeHeader.cpp` (structural command checks)

## Completion boundary

MAC-0 can be qualified as a **static parser/security-contract milestone**
only after its new and inherited exact-head CI passes. Neither MAC-0 nor
MAC-1 to MAC-7 establishes certified macOS application compatibility,
production security, Apple Silicon support or hardware release.
Final one-time merge remains blocked until the user-approved named profile's
remaining required gates and kernel regressions are independently verified.
