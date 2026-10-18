<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.7 — macOS Mach-O amd64 foundation (metadata only)

This is **NOT** macOS compatibility or application execution. It provides a standalone and bounded Mach-O x86_64 64-bit metadata validator for feasibility research.

- Supports a narrow synthetic non-PIE MH_EXECUTE image with LC_SEGMENT_64 and LC_MAIN and unlinked metadata commands.
- Rejects dylib/dyld load commands, code-signature, thread-state, PIE, writable-executable segments, malformed load commands, memory-range overflow and non-file-backed entrypoints.
- Verifies header, segment layout, address space, and entrypoint metadata; never maps executable pages, loads frameworks, enters the application, or interprets Darwin/BSD syscalls.
- ARM64 Mach-O is explicitly unsupported by the AMD64-only kernel.
- Typical macOS programs require PIE, dyld, code signing, Objective-C runtime, Mach messaging, CoreFoundation, AppKit, Metal and many other frameworks. None are implemented.
- Test inputs are synthetic, without distributing Apple binaries or SDK resources.

Security boundaries: preserve lower-half user address restrictions in any future adapter, prevent privileged native filesystem access, and do not mount host macOS resources via /compat/macos without isolation and permission checks. The source directory ryzova/compat/macos is **not** a kernel-mounted runtime directory.

Verification: GCC and Clang with strict warnings-as-errors and UndefinedBehaviorSanitizer, plus freestanding compilation. Existing Native Ryzova QEMU CI tests kernel regressions, not Darwin application execution.
