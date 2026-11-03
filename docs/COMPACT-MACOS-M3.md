<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Compact macOS MAC-3A — inert Mach-O dylib dependency metadata

**Security posture: metadata-only, original C implementation.**
This is not dyld, symbol resolution, relocation, code-signing, runtime
loading, app launch or a guest-/host-filesystem service.

The original bounded C API `ryz_mac3_scan()` parses the little-endian
Mach-O64 Intel x86_64 `MH_EXECUTE` and `MH_DYLIB` metadata profiles with
max 4-MiB input, max 32 load commands / 16 segments, 8 named dependencies,
4 rpaths and 192 bytes per path. These ceilings are independent of the
host filesystem, application claims or available resources.

**Allowed names are inert ASCII strings**, from:
`/usr/lib/`, `/System/Library/`, `@rpath/`, `@loader_path/`,
`@executable_path/`. Invalid components such as `..`, `.`,
duplicate slashes, control characters and non-allowlisted absolute paths
are rejected; there is **no filesystem resolution or library search**.
A `LC_LOAD_DYLINKER` name must match literal `/usr/lib/dyld`. The
supported manifest inventory commands are `LC_SEGMENT_64`,
`LC_MAIN` for `MH_EXECUTE`, `LC_LOAD_DYLIB`, `LC_ID_DYLIB` for
`MH_DYLIB`, `LC_RPATH`, `LC_LOAD_DYLINKER`, and fixed-size
`LC_UUID`/`LC_BUILD_VERSION`/`LC_VERSION_MIN_MACOSX`.
Unexpected commands including symbol tables, bind/rebase/fixup streams,
code signatures and thread startup are explicitly denied, not ignored.

A success result guarantees **only bounded command/manifest geometry**.
The scanner never maps executable bytes, reads a host file or attempts
to link a guest dependency. Its probe prints `native_guest=0`,
`dylib_loading=0` and `symbol_resolution=0` on every result.
MAC-3A will not be declared accepted until exact-head Clang/GCC sanitizer
and independent CI jobs pass. Such PASS is a narrow scanner milestone
and does not complete MAC-3 full dynamic linker / libSystem support.

## Next genuine MAC-3 gates still open

1. A scoped native Ryzova ABI, with verified memory isolation and
   admission identity for each guest process.
2. Validated Mach-O `LC_SYMTAB`, dyld bind/rebase/chained fixups and
   code-signing policy; symbol resolution with correct library lifetimes.
3. Original restricted dynamic loader and `libSystem` runtime surface,
   implemented lawfully without copying Apple-proprietary SDK binaries.
4. Pinned open-source macOS command-line reference programs run in a
   real Ryzova guest, with independent host-vs-guest output equivalence.
5. Fault handling, fuzz/negative cases, native source-built QEMU and
   all driver/security regression workflows on the **exact final head**.

All of MAC-4–7 remain unimplemented/unqualified in the present PR.
