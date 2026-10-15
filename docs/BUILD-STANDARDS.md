# Ryzova Kernel build, source and release standards — Phase 2

These conventions guide future kernel development and downstream variants. They do not change imported 9front files in Phase 2.

## Source layout

- Retain upstream 9front source layout, including `sys/src/9/pc64` (AMD64), `sys/src/9/port`, platform directories and `lib/legal`. No mass moving/renaming.
- Keep `main` as Ryzova integration branch and `upstream/front` as a **pure upstream history mirror**.
- Future Ryzova-specific modules get distinct names/paths and SPDX headers when developed in Phase 3+.
- Do not replace original driver copyright headers or graft Ryzova licensing over inherited sources.

## Tooling

- The native 9front build system uses **`mk` and Plan 9 toolchains**, not GNU `make`. Consult `sys/src/9/pc64/mkfile`.
- Pin all baseline source revisions and toolchain/VM image checksums.
- Store human-readable build recipes and logs without embedding secrets.
- Build in isolated, non-privileged CI contexts where possible. Do not execute unreviewed upstream build scripts with repository-write credentials.
- No release without recorded **native compilation and QEMU boot logs**; the source-integrity CI check is not a kernel build test.

## Version and compatibility plan

- Until Phase 3 delivers verified Ryzova boot artifacts, refer to the repository as **Phase 1/2 pre-release source**. Do not claim stable Ryzova kernel version or binary compatibility.
- Proposed future Ryzova releases will document the upstream commit SHA, Ryzova patchset revision, toolchain version, target architecture, hardware support/known issues and ABI stability.
- Preserve upstream 9P and namespace interfaces unless a documented reviewed change is warranted. Version external interfaces explicitly if they evolve.

## Pull request quality gates

1. Legal origin and correct file-level SPDX/license notices.
2. Source-provenance test and license-inventory workflow.
3. Native build and QEMU smoke boot, once a verified baseline is available.
4. ABI/driver regression and security review, as applicable.
5. Maintainer approval before merging upstream imports or cutting a release.

See [`BUILD.md`](BUILD.md) for current pending amd64 boot work.
