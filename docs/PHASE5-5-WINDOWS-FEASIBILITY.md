<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.5 — Windows x64 compatibility feasibility and boundaries

**Not Windows app support.** This phase provides a strict PE/COFF PE32+ x64 *metadata* parser and architectural threat model. No PE instructions execute, no Windows DLL loaded, no Win32/NT syscalls or kernel graphics/audio/UI imported.

## Proposed layering
PE image structure and sections -> relocations/import loader -> Windows x64 calling convention -> Windows NT process/object/handle subset -> Win32 user-mode API shims and DLL semantics -> Ryzova's isolated process, virtual filesystem and IPC interfaces. The above components after the first are still unimplemented. A namespace path or PE reader cannot make a Windows app run.

We begin with MZ/PE headers, AMD64 machine, PE32+ optional header, image base, virtual section sizes, file boundaries, section RVA and entrypoint checks. Reject executable+writable sections, overlapping sections, image sizes over 64 MiB, DLLs, imports, exception directory, base relocations, TLS, CLR/.NET and unsupported formats. The parser does not map executable memory or load DLLs.

## Technical feasibility
- **Potential:** selected freestanding x64 PE with no imports can be structurally inspected and described without executing it.
- **Requires research:** ASLR relocations, structured exception handling, NT runtime, Win32 APIs, DLL loader, UTF-16 APIs, handles, message loops, graphics stack, COM, security tokens, registry, process synchronization.
- **Prohibited claims:** Windows application execution, Windows driver ABI compatibility, NT kernel binary compatibility or Wine-equivalent coverage.
- **Security/legal:** all PE bytes are untrusted; deny W+X and file/VA overflows; preserve provenance, do not copy proprietary Windows system DLLs; review licensing and potential patents. Never expose privileged Plan 9 resources via implicit `/compat/windows` bind.

Unit tests create synthetic standalone PE32+ AMD64 headers and reject unsafe variants under GCC and Clang UndefinedBehaviorSanitizer; a successful metadata parse is **not** executable integration.

Keep Phase 5 changes on draft branch until the entire Phase 5 series is verified and user approves merging to `main`.
