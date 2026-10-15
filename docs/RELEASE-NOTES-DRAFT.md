# Ryzova Kernel — AMD64 developer preview (DRAFT, NOT PUBLISHED)

Status: **NOT RELEASED**. This template must not be presented as an official release until responsible Ryzova maintainers approve Issue #9 and redistribution rights under Issue #3.

## What is verified

- 9front-derived AMD64 `9pc64` built with native `mk` from a recorded Ryzova Git checkout.
- Freshly built QEMU kernel booted to native `rc`; `#Z/version` reads `Ryzova Kernel 0.1.0-dev`.
- `#Z` is read-only; 9P ramfs read/write, 9fat mount/read, /proc, /net, namespace bind and VirtIO HTTP traffic passed functional smoke tests.
- Guest compiled file SHA256, guest bootfile SHA256 and independent host-extracted SHA256 matched.

Evidence: https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38708363099

## Values to fill and review before release

- Exact final **main source commit**: [REQUIRED]
- 9front upstream base source SHA: `a0806493926c04ce90d4e4a46961dec30a1054dd` (update if changed)
- Final release source archive / kernel artifact SHA256: [REQUIRED — recompute for final release]
- Exact verified native 9front builder image: `9front-11952.amd64.qcow2.gz`
- Builder image digest SHA256: `3c1b57c4b609525e76cb0abac48bc657f71187fd3506674dba4e49b42141729c` (digest pinned for integrity, independently authenticated signature not established)
- Build and QEMU commands: `docs/BUILD.md`, `scripts/phase3-native-build.py`
- Release-asset file list and file-level license inventory: [REQUIRED]
- Owner/licensing/trademark approval record: [REQUIRED]
- Security advisory and third-party notices review: [REQUIRED]
- Signatures, if used: [REQUIRED]
- Actual reproducibility check by maintainer other than original implementer: [REQUIRED]

## Limitations

This is **experimental**, no stable ABI or Linux/Windows/macOS binary compatibility claim, no certified physical hardware coverage, no RyzovaOS desktop. More complete kernel regression, fuzzing and security assurance are required before production deployment.

**Do not attach or release the binary** until rights to distribute the actual artifact, including embedded files, are verified. The CI deliberately deletes temporary kernel binary before artifact upload while this remains unresolved.
