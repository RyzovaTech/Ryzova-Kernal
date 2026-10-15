# Ryzova Kernel baseline build and boot verification

**Status (updated 2026-10-15): the experimental Ryzova AMD64 source kernel has been built with native 9front `mk` and successfully booted under QEMU.** The verified [CI run](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38703531423) includes device identity and read-only checks. This is not hardware certification, an end-user release, or full network/storage regression clearance.

## Current pinned baseline

Upstream: `9front/9front`, branch `front`
Initial baseline SHA: `a0806493926c04ce90d4e4a46961dec30a1054dd`

The upstream source is at repository root. The amd64 kernel is under `sys/src/9/pc64/`. The build recipe is `sys/src/9/pc64/mkfile`. Source build depends on Plan 9 / 9front tooling and libraries, not GNU make.

## Source provenance checks (GitHub Actions)

`scripts/verify-foundation.sh` verifies upstream ancestry, key 9front sources, and retained license notices. This is **not** a substitute for a native compile or QEMU boot.

## Native build gate — implemented in experimental QEMU CI

1. Pin a known working 9front system / toolchain image with source URL and checksum; do not use an unverified “latest” download.
2. In a disposable VM using the pinned image, install or mount exactly this imported source tree with the correct Plan 9 paths and `amd64` tools.
3. From the native 9front shell, use the kernel's standard mkfile, e.g. `cd /sys/src/9/pc64; mk`, after ensuring the kernel configuration and supporting libraries are built correctly.
4. Save complete build logs, toolchain details, input commit SHA and produced kernel file checksum.
5. Boot the **built** amd64 kernel in QEMU and capture serial/console output.
6. Run checks for device initialization, memory allocation, network access, basic 9P mounts and process management.
7. Record results and enable an automated, checksum-pinned VM build job only after the above procedure passes.

The native build and source-built QEMU userspace boot gates are demonstrated with logs. The [Phase 3.5 run](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38708363099) also verified actual 9P ramfs/file I/O, 9fat mount, VirtIO HTTP GET, and three matching kernel binary SHA256 values (compiled guest file, installed guest file, independently extracted host file). **Remaining:** broader stress/performance tests, real physical hardware certification, approved redistribution, and any public developer-preview binary. See `docs/PHASE3.md` and `docs/PHASE3-5-RELEASE-GATES.md`.

## Developer workflow

Keep upstream updates in `upstream/front`. Create a review branch from `main` for proposed integration. Preserve Git ancestry and run CI. Before any release, review license changes, successful native build, and QEMU boot evidence. No auto-merge of 9front updates into `main`.
