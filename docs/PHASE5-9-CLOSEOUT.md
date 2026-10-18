<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.9 — Experimental foundation closeout and Phase 6 research handoff

## What passed

Source foundations 5.0–5.8 implement and test: ELF64 Linux static load-plan, virtual Linux syscall and path policy, a deliberately bounded x86-64 ELF interpreter **on CI's Linux host**, PE32+ Windows x64 metadata validator, Intel x86_64 Mach-O metadata validator, deterministic adversarial parser checks, and a fail-closed compatibility matrix.

Phase 5.9 runs the **entire** Phase 5 test pattern on GCC and Clang, with UndefinedBehaviorSanitizer and negative acceptance assertions. It records an SHA256 inventory of audited input files and verifies the separately maintained kernel release gate remains BLOCKED. The independent native AMD64 QEMU workflow continues to provide kernel boot/non-regression evidence, not Linux app execution. Require it to pass for the exact PR commit before integrating into main.

## User-approved source merge is not application-compatibility certification

The user requested merge of Phase 5 work and Phase 6 readiness. Therefore **experimental foundation code may be merged into main** as research/developer infrastructure after all tests pass. This does NOT imply:
- Ryzova can natively launch a Linux executable or run general-purpose Linux apps;
- Windows PE or macOS Mach-O executables run (only headers/layout metadata are inspected);
- `/compat/linux`, `/windows` or `/mac` namespaces are mounted in the live kernel;
- applications are isolated by a verified kernel security boundary or can be publicly distributed;
- independent physical hardware, licensing or long-running kernel stability gates are complete.

The separate `phase5-status.json` / Phase 5.8 matrix deliberately retains `phase5_full_completion=false` and `merge_to_main_permitted=false` as **production-compatibility readiness** indicators. The explicit Phase 5.9 manifest records the **narrow research-source merge request**, not production authorization.

## Native Linux-app proof that still must be demonstrated

To truthfully claim Linux application execution in Ryzova Kernel: port code into an appropriately isolated Plan 9/Ryzova userspace or kernel integration, implement guest executable mapping and initial register/stack/auxv state, wire Linux syscalls through a safe native trap mechanism, and demonstrate output plus exit from an actual statically linked Linux ELF under **source-built Ryzova Kernel QEMU**. Existing host-interpreter output cannot substitute for this test. This remains a tracked technical debt item after Phase 5 experimental source merge.

## Phase 6 handoff

Phase 6 is **Optional External Resource Services**, subject to standalone trust and failure gates. This is not a promise of literal remote CPU or remote physical RAM. Refer to [PHASE6-ENTRY.md](PHASE6-ENTRY.md). No Phase 6 network service code ships as part of Phase 5.
