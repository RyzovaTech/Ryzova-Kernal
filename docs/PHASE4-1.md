# Phase 4.1 — Memory, Scheduler, Process and Security Stability

**Scope:** bounded, reproducible experimental AMD64 QEMU tests of the freshly source-compiled Ryzova Kernel, with failure evidence and release limits. This phase does **not** modify drivers or 9front sync, and does **not** claim hard real-time scheduling, production security, verified physical hardware, or indefinite stress stability.

## Preconditions

Phase 4.0 baseline remains pinned at d6b1f3d8e78470f5ae9caf42d85deb983239e752 and the last known-good AMD64 branch is retained. The Phase 3 source-built QEMU workflow must continue to compile exact checked-out kernel source, verify installed kernel bytes and hash, restart QEMU, enter native rc, and pass 9P/storage/network/interface regressions. No test is valid solely because QEMU launched or a command was echoed to the terminal.

## Phase 4.1 runtime scenarios

The native-QEMU harness runs all scenarios **after** the existing freshly built kernel identity, 9P ramfs read/write, FAT bootfile and VirtIO HTTP tests. The scenarios in [phase4_1_stability.py](../scripts/phase4_1_stability.py) are strictly bounded:

| Group | Guest action | Evidence required |
| --- | --- | --- |
| Memory | Read /dev/swap before work | Parsed total memory, page size, user/swap used/total; valid numerical ranges |
| Bounded allocation / I/O | Write exactly 128 blocks of 4096 bytes to disposable in-guest ramfs | wc reports **524,288 bytes**; no unbounded pressure |
| Process lifecycle | Launch a short sleep child and wait for that PID | Standalone positive marker after successful wait |
| Scheduler progress | Launch two finite children and wait for **both** | Standalone positive completion marker; not a fairness/latency benchmark |
| Process observability | List active processes with ps; confirm rc entry | Standalone successful enumeration marker |
| Memory consistency | Re-read /dev/swap | Consistent total RAM/page size, user/swap counters remain within bounds |
| Security (Phase 3 regression) | Attempt writing #Z/version, expect permission denied, then read again | Denied write + subsequent successful read, verified from fresh-boot output |

All commands run within a disposable 2 GiB RAM, two-vCPU virtual machine, under a fixed QEMU runtime deadline. The test harness has no GitHub write credentials, cannot deploy binaries, and is stopped after collecting serial evidence.

Positive **output** must occupy a complete serial line; a command echoed back by the terminal must not satisfy a check. Negative results fail the test; a final marker alone is not proof if a scenario failed earlier. The [unit tests](../tests/test_phase4_1_stability.py) deliberately inject forged markers, incomplete allocation, invalid memory stats and missing completion.

## CI and evidence

The existing [native AMD64 build workflow](../.github/workflows/phase3-native-build.yml) now runs Phase 4.1 scenarios and fails on any failed assertion. Outputs include:

- Native source revision, source archive digest and built-versus-installed kernel checksum verification.
- The freshly booted guest serial log.
- Machine-readable artifacts/phase3/phase4-1-stability.json with every check, parsed memory totals, and explicit unverified categories.
- Existing 9P, FAT storage, VirtIO HTTP and kernel identity evidence.

The [Phase 4 baseline workflow](../.github/workflows/phase4-baseline.yml) runs Phase 4.0 source/rollback checks and Phase 4.1 parser/negative-path unit tests. In addition, the native QEMU workflow is triggered when Phase 4.1 scenarios or kernel-related files change.

## Realistic limitations

These tests establish **basic progress and no immediate regressions** for bounded loads. They do not measure CPU fairness, deadline scheduling, process stress at scale, leak rates over hours, OOM recovery, privilege-boundary completeness, side channels, memory corruption, or real-hardware SMP/NUMA timing.

Extensive fault injection, repeated multi-hour soak, memory exhaustion tests, security fuzzing, hardware driver validation, release signing and physical recovery remain separate gates. Do not market Ryzova as a secure/hardened or physically certified kernel based on this phase.

## Acceptance

1. Phase 4.0 frozen baseline unchanged; retired 9front sync workflow remains absent.
2. Phase 4.1 parser unit tests pass, including negative/error cases.
3. Fresh native AMD64 compilation, QEMU second boot, 9P/storage/network, kernel identity, read-only protection, and every Phase 4.1 scenario pass **on the same PR head**.
4. PR reviewed/merged only after CI, then equivalent main-branch native CI passes.
5. Docs and evidence identify what remains unverified rather than declaring unconditional stability.
