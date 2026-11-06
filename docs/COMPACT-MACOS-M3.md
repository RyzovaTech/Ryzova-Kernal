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

## MAC-3B — inert Mach-O object symbol inventory

The original `ryz_mac3_symbols()` C parser inspects only little-endian
x86_64 `MH_OBJECT` nlist_64 and `LC_SYMTAB` metadata. It rejects unknown
load commands, oversized/unbounded symbol tables, invalid string-table
ranges, duplicate names, unsupported symbol types, stale relocations and
untrusted names. It classifies defined vs undefined externally visible
symbols and counts bounded relocation entries. **It never resolves, binds,
applies relocations, accesses host libraries or executes guest code.**
The dedicated test corpus includes a *genuine* Clang Darwin x86_64
`MH_OBJECT` with an unresolved external symbol `_missing_symbol`.
This illustrates why actual dyld/linker work and kernel trust policies
remain essential rather than substituting a host implementation.

## Reproducible source-built metadata evidence

`python3 scripts/compact_macos_m3_demo.py` compiles a genuine
Clang x86_64-apple-macosx13.0 relocatable Mach-O object with an
unresolved `_missing_symbol`, builds the original Ryzova C symbol
metadata parser and classifies `_ryz_entry` and `_missing_symbol`
as defined/undefined without binding. It separately scans an original
synthetic executable dependency manifest naming `libSystem.B.dylib`
and literal `/usr/lib/dyld` **without loading either library**.
The JSON evidence contains independent SHA-256 digests and explicitly
false flags for dynamic linking, guest execution, and application
compatibility. The macOS-host MAC-3 CI job archives that result.

## MAC-3C — first *actual* bounded interobject linker proof

The original `ryz_mac3_link2()` now consumes **two independent,
source-built x86_64 Darwin `MH_OBJECT`** files. It accepts one bounded
`__TEXT,__text` section per file, verifies the external `nlist_64`
symbol definitions against unresolved references and applies only
explicit `X86_64_RELOC_BRANCH` signed 32-bit PC-relative relocations
(the sole admitted relocation kind). Unknown relocations and symbol
types, ambiguous/duplicate definitions, references outside bounded
file/virtual ranges, nonzero addends and unsupported commands are
explicitly denied.

The linker synthesizes a deliberately restricted static
`MH_EXECUTE` **test fixture** with one RX mapping and `LC_MAIN`.
The original **host-only Ryzova VM** interprets the entry code, which
calls a function defined in the other Mach-O object and returns EAX=42.
This goes beyond metadata inventory by **actually resolving a cross-object
symbol and relocating the branch instruction**.

Run `python3 scripts/compact_macos_m3_link_demo.py` to build genuine
Clang-generated AMD64 Darwin objects, invoke the independent C linker
and restricted interpreter, and produce JSON with SHA-256 hashes and
explicitly false native/dyld/libSystem/application claims. CI runs
MAC-3C positive/negative tests on macOS Clang and Linux GCC/Clang.

This is **not** a Mach-O dylib linker, dyld, shared cache,
`libSystem`, Objective-C, full relocations, process ABI, native Ryzova
guest or production macOS app compatibility. MAC-3 full completion remains
blocked on genuine dynamic library binding and native guest qualification.
