<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.0 — Linux compatibility architecture (EXPERIMENTAL)

## What Phase 5 is
A new *optional*, separately testable Linux compatibility subsystem in Ryzova Kernel's 9front-derived architecture. The primary Plan 9 kernel ABI, 9P, namespaces and existing native services stay intact. Linux executable compatibility is **not yet supported**; the Phase 5.1 component does **not** run ELF images.

## Trust boundary and execution model
```text
Untrusted Linux ELF file (read-only bytes)
  -> Phase 5.1 ELF64 structural validator + load PLAN (host-tested portable C)
  -> Phase 5.2+ executable image mapping and Linux syscall translation
  -> Phase 5.3+ Plan 9-compatible namespace /compat/linux runtime view
  -> Phase 5.4+ verified Linux userspace execution in isolated QEMU
```
The parser does not allocate executable pages, transfer control to an entrypoint, mutate the native Plan 9 kernel loader or call Linux syscalls. Its output is metadata, *not a running program*. Later adapters must enforce process address-space isolation, safe segment mapping, user/stack/heap/TLS setup, validated syscall numbers/arguments, openat-style path access, signals, file-descriptor translation and user credentials. Mapping must never expose kernel memory; translate guest pointers with explicit range checking.

## Namespace model
`/compat/linux` is a proposed **per-process namespace view** for Linux-like runtime resources and emulated services. It is not a virtual machine, an automatic device filesystem mount, or a magical executable translator. It may eventually provide virtual `proc`, `dev`, `tmp`, `sys` and immutable runtime shared objects, but exposing privileged host namespaces directly is forbidden.

## Security constraints
- File-sourced bytes are untrusted; bounds-check every byte range and integer arithmetic before copying or mapping.
- Reject unsupported ELF classes, architectures, relocatable/PIE images, ELF dynamic interpreter, PT_DYNAMIC and TLS until explicit handling exists.
- Enforce W^X; entry must land on file-backed executable bytes; no executable stack.
- Limit executable headers, segments, mapped address sizes and legal user virtual address range.
- Do not execute binaries with elevated Plan 9 privileges; future Linux syscalls operate only through a separately reviewed restricted process interface.
- Never assume Linux kernel GPL driver code can be copied into this AGPL-authored subsystem; use primary ELF/ABI specifications and reviewed code provenance.

## Scope and road map
**5.0** Architecture and threat model; **5.1** ELF64 static ET_EXEC load planning and segment materialization test library; **5.2** execution-space loader adapter and initial Linux AMD64 syscall ABI, including negative syscall tests; **5.3** isolated `/compat/linux` namespace; **5.4** genuinely execute a small Linux static hello/exit application in QEMU; **5.5+** separately assess dynamic linker, PIE, TLS, security, Windows/macOS feasibility.

## Release and integration policy
All Phase 5 changes remain on `phase5/linux-elf-foundation` and draft PR until full Phase 5 tests and user-approved merge. Do not update `main` or reactivate retired 9front synchronization. This architecture does not extend the experimental-0 stable kernel contract or imply any certified compatibility.
