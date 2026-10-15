# Pre-Phase-3 boot and build verification

Phase 3 must **not** be started on the assumption that a successful file-layout check or an official 9front VM boot proves this repository's kernel is bootable.

## Verification gates (distinct evidence required)

| Gate | What it proves | Status before tests |
| --- | --- | --- |
| V0 — Source/history/license notices | Original upstream source and key license notices were imported without losing Git ancestry | PASS, from existing foundation CI |
| V1 — Official 9front VM smoke | A *separately distributed, prebuilt 9front release image* starts its kernel under QEMU | **PASS for kernel initialization** (not user-space shell), run 38692092989 |
| V2 — Ryzova source native compile | The files at a recorded `Ryzova-Kernal` commit compile to a fresh AMD64 kernel with the correct 9front `mk` toolchain | NOT RUN |
| V3 — Boot freshly built kernel | The **V2 artifact** boots under QEMU with recoverable boot logs and matching checksum | NOT RUN |
| V4 — Basic runtime checks | Booted V3 kernel reaches user space and provides 9P, local storage, network, basic process/memory functions | NOT RUN |
| V5 — Physical hardware | The kernel works on explicitly listed hardware IDs / platforms | NOT RUN |

The diagnostic workflow [`prephase3-qemu.yml`](../.github/workflows/prephase3-qemu.yml) downloads **9front-11952.amd64.qcow2.gz** from the [official release archive](https://build.9front.org/release/), records the downloaded SHA256 and launches its **prebuilt** kernel in QEMU. This can at most satisfy V1. It must **never** be counted as a successful build/boot of Ryzova's repository source. On 2026-10-15, [upstream release QEMU run #38692092989](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38692092989) captured a guest serial log containing `Plan 9`, two detected CPUs, a VirtIO network interface, memory accounting, `/dev/sd00` disk partitions, and the `bootargs` prompt. This **proves kernel initialization**, not a successful transition to a userspace shell; the latter remains to be demonstrated. If serial output does not show a definite 9front marker, the V1 job fails and records a screenshot for manual investigation.

### Unresolved reproducibility requirement

The official image is pinned by *release filename* and a SHA256 observed in the passing test (`3c1b57c4b609525e76cb0abac48bc657f71187fd3506674dba4e49b42141729c`). This verifies bytes are stable on subsequent runs but **is not independent authenticity verification**. Before long-term dependency on this VM, verify the digest against an independent trusted source or upstream signature.

## Upstream compilation evidence: source parity (not a Ryzova-built binary)

9front's public [nightly build index](https://build.9front.org/) records a **passing build (12077)** for upstream commit `9c7543976c3e9614ddd61c1173aaa754aff5e1d5`. The Ryzova import is upstream commit `a0806493926c04ce90d4e4a46961dec30a1054dd`, exactly **one commit newer**. The only change between these commits is `sys/src/games/aout2gba.c`, outside the kernel. CI `scripts/verify-foundation.sh` checks that precise diff and fails if it changes.

**Conclusion:** the imported source's **kernel files** are unchanged from the upstream nightly build source. This is strong external compile evidence, **but not a native compilation of the Ryzova repository**, not a fresh kernel checksum, and not a successful boot of the kernel artifact from this branch.

## V2: native build plan (not yet completed)

After V1 diagnostics, use a version- and checksum-pinned installed 9front build environment, transfer this repository's exact source revision to the guest, and run its real `mk` build, not a Linux host compile.

Example **inside a properly prepared, disposable 9front VM** (not a Linux shell):

```rc
cd /sys/src
objtype=amd64 mk install
cd /sys/src/9/pc64
mk
```

Build prerequisites, copied source tree layout, toolchain versions, logs and kernel SHA256 are required. **Do not boot the release's original prebuilt kernel and label it the output of this build.**

## V3: QEMU boot of V2 artifact (not yet completed)

Prepare a 9front bootloader and Plan 9 boot configuration pointing **specifically** at the built `/amd64/9pc64` artifact. Capture QEMU serial/video evidence of the newly compiled kernel reaching boot and userspace. Confirm the boot file checksum matches the V2 output, and record exact source commit.

## V4: Runtime check plan

Check startup, CPU count, kernel memory reporting, basic process creation, local filesystem, 9P mount, network device detection/traffic and graceful shutdown. Hardware support is only confirmed for specific devices under test.

## Phase transition rule

Proceed to Phase 3 kernel changes only after reporting the actual V0–V3 results; any pending gate must remain explicitly pending, with actionable blockers and reproducible logs. Distinguish **test harness delivered** from **kernel actually boot-verified**.
