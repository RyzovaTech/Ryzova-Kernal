# Ryzova Kernel baseline build and boot verification

**Status: not built or boot-tested.** Phase 1 imports the untouched 9front source and establishes checks; a successful structural CI check does **not** mean the kernel compiled or booted.

## Current pinned baseline

Upstream: `9front/9front`, branch `front`
Initial baseline SHA: `a0806493926c04ce90d4e4a46961dec30a1054dd`

The upstream source is at repository root. The amd64 kernel is under `sys/src/9/pc64/`. The build recipe is `sys/src/9/pc64/mkfile`. Source build depends on Plan 9 / 9front tooling and libraries, not GNU make.

## Source provenance checks (GitHub Actions)

`scripts/verify-foundation.sh` verifies upstream ancestry, key 9front sources, and retained license notices. This is **not** a substitute for a native compile or QEMU boot.

## Required native build gate — to be executed and logged

1. Pin a known working 9front system / toolchain image with source URL and checksum; do not use an unverified “latest” download.
2. In a disposable VM using the pinned image, install or mount exactly this imported source tree with the correct Plan 9 paths and `amd64` tools.
3. From the native 9front shell, use the kernel's standard mkfile, e.g. `cd /sys/src/9/pc64; mk`, after ensuring the kernel configuration and supporting libraries are built correctly.
4. Save complete build logs, toolchain details, input commit SHA and produced kernel file checksum.
5. Boot the **built** amd64 kernel in QEMU and capture serial/console output.
6. Run checks for device initialization, memory allocation, network access, basic 9P mounts and process management.
7. Record results and enable an automated, checksum-pinned VM build job only after the above procedure passes.

No boot success or driver compatibility is claimed until gates 1–7 have evidence.

## Developer workflow

Keep upstream updates in `upstream/front`. Create a review branch from `main` for proposed integration. Preserve Git ancestry and run CI. Before any release, review license changes, successful native build, and QEMU boot evidence. No auto-merge of 9front updates into `main`.
