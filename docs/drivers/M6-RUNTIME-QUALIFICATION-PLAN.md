<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase M6 — Runtime Qualification and Server Reliability Plan

Status: ENGINEERING PLANNING ONLY. No M6 runtime, server, or hardware release is certified.

## Immutable starting evidence

- Base: main 048e457e0a2d15b5a0a85569a0ccaa70c3a3583e (M5 PR #46 merged, Phase 7 guest TLS merge later).
- M5 PR #46: native ARM64 7c source compile verified. Full ARM64 9qemu, QEMU boot, VirtIO I/O, SMP/GIC/IRQ, DMA/IOMMU and physical hardware remain unqualified.
- M5.5 draft PR #49 owns bootfs paqfs/factotum cross-bootstrap and the initial ARM64 build and boot CI probing. It must not be duplicated, overwritten, or treated as passing until its exact-head runs finish successfully.
- Phase 7 PR #48 owns guest TLS ingress/recovery. Do not modify its four paths or merge it as part of M6.
- Driver agent owns concurrent D-series / low-level device implementations. No automatic 9front sync, no speculative hardware certification, no candidate-as-driver counting.

## M6.0 — Evidence inventory and baseline lock

Capture immutable commit SHA, test commands, QEMU machine/cpu/image hashes, compiler and toolchain provenance, kernel provenance, guest serial transcript and exit conditions. Keep AMD64 fresh boot, 9P, storage and networking CI mandatory. Preserve modern AMD64 desktop/laptop, AMD64 server and legacy AMD64 test profiles. Do not treat GitHub Actions queued/pending checks as pass.

Gate: documented, reproducible evidence schema with missing and unknown results failed closed.

## M6.1 — ARM64 boot dependency closure (depends on PR #49)

Review native paqfs and factotum bootstrap outputs, cross-compiler architecture, bootfs contents and exact 9qemu/9qemu.u linker outcomes. Eliminate dependencies by producing verified ARM64 artifacts, never by skipping prerequisites. Record host/guest image SHA256 and complete boot logs, panic/watchdog/timeout outcomes.

Gate: compiled+linked native ARM64 boot image AND a fresh qemu-system-aarch64 virt boot reaching an independently checked guest readiness marker. If either absent, BLOCKED.

## M6.2 — QEMU ARM64 VirtIO functional qualification

Use an isolated guest test filesystem and test network, exercising actual guest-side VirtIO-net RX/TX with packet checks and VirtIO-blk read/write/flush with SHA256 before/after, power loss/reboot fault cases. Reject host-only emulator or static registry checks as hardware support.

Gate: clean guest boot, deterministically verified network I/O and block integrity, reproducible artifacts.

## M6.3 — ARM64 SMP/GIC/IRQ and DMA/IOMMU safety

Verify multi-vCPU start/stop and CPU-affinity behavior, per-interrupt dispatch, IRQ storms and reentrancy, registration/unregistration races, DMA bounds, device teardown and mapping failure. Distinguish emulated IOMMU coverage from real SMMU hardware tests and mark unimplemented mechanisms NOT TESTED.

Gate: repeatable stress/fault evidence with no hangs, memory corruption, silent fallbacks or falsely claimed IOMMU isolation.

## M6.4 — Server reliability and recovery

For ARM64 and AMD64 server profiles: long-lived 9P/network/storage soak, attach/detach, simulated I/O failures, reboot and clean shutdown, bounded retries and backpressure, machine health visibility and recovery markers. Separately verify remotely sourced TLS/9P only after the independent Phase 7 change is merged and approved; do not silently accept plaintext fallback.

Gate: defined soak durations, measured fault-injection outcomes and intact prior regressions.

## M6.5 — Scalable qualification of modern and legacy drivers

Evidence catalog per PCI/USB ID and firmware variant: source candidate -> built -> QEMU exercised (if applicable) -> physical test observed -> qualified model. No implication between statuses. Require exact test hardware, bus topology, kernel hash, driver/version, observed functions, negative cases, reproducibility and reviewers. Modern AMD64 desktop/laptop and server stay highest expansion priority, but legacy boot/PS2/ATA/PCI and non-UEFI regressions are permanent release blockers. ARM64 driver data has a separate qualification track.

Gate: no lost baseline support; zero additional physically certified models until independently evidenced.

## M6.6 — CI, review, merge and release discipline

- Branch-per-isolated-feature; keep M5 PR #49 and Phase 7 PR #48 ownership and test files intact.
- CI matrix: Linux host unit tests; pinned native ARM64 build; true ARM64 guest boot; real guest I/O; AMD64 fresh native QEMU 9P/storage/network; modern and legacy platform regressions; licensing and disabled-sync checks.
- Fail closed on skipped, missing, queued, unknown or inconclusive checks. Keep a strict distinction between source-engineering merge readiness and hardware release.
- Before merging verify exact PR head and all applicable checks, inspect diff for conflicting PRs, and rerun on the new base after concurrent merges.
- Hardware release requires independently documented physical ARM64 and AMD64 server/desktop/legacy tests; no automated CI alone suffices.

## First execution order

1. Finish reviewing PR #49 exact-head workflow evidence and solve any ARM64 paqfs/factotum/link/boot blockers on that PR's own ownership track.
2. Establish M6-specific fail-closed runtime evidence inventory and immutable baseline without changing driver or TLS source.
3. Add ARM64 guest VirtIO I/O integration only when a booted ARM64 kernel exists.
4. Stress SMP/GIC/IRQ/DMA; then server soak and per-device physical qualification.
5. Merge M6 code only on green current-head CI and no concurrent conflicts; otherwise retain as draft.

Release indicators: M6 planning = open; M6 source integration = pending; M6 ARM64 runtime = blocked until actual boot+I/O evidence; M6 physical hardware certification = blocked; newly certified physical models = 0.
