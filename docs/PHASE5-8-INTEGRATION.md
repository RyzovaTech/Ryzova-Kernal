<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.8 — Cross-platform integration inventory, NOT release certification

The independent static/dynamic host test workflows now cover three mutually different maturity levels:

| Platform | Implemented in Phase 5 draft | Still absent |
|---|---|---|
| Linux AMD64 | Real static ELF instruction subset interpreted in host-only virtual engine, ELF loader, virtual Linux syscall mock, virtual namespace policy | Running arbitrary Linux apps or native process under Ryzova Kernel QEMU, real kernel trap/exec integration, actual mounts and dynamic linker |
| Windows AMD64 | Bounded PE32+ executable metadata reader | NT/Win32 API, DLL, relocations, executable runtime, actual Windows app |
| macOS Intel AMD64 | Bounded Mach-O metadata reader | dyld, Mach/BSD syscalls, frameworks, process runtime and native app |
| macOS ARM64 | No binary support | Different CPU architecture and entire runtime |

`ryzova/compat/phase5-status.json` records only documented support. `scripts/phase5_matrix.py` validates the 5.0–5.8 source contracts and refuses falsely elevated status for native application execution, Windows/macOS execution, public release or merge authorization. It produces SHA256 evidence for inspected files.

The original kernel's native QEMU boot CI remains necessary for regressions, but is **not** proof that new userland parser/VM code has been integrated into the kernel. The source directories are not mounted `/linux`, `/windows` or `/mac` runtime paths.

**Completion policy:** 5.8 inventory infrastructure can be finished while *full Phase 5 compatibility* remains incomplete. Keep Draft PR #34 unmerged; before the user-authorized merge, implement/verify the defined native Ryzova Linux app execution acceptance gate or revise Phase 5 scope explicitly with the user. Continue security review for real privilege and memory isolation, and do not mislabel bounded fuzz tests a full audit.
