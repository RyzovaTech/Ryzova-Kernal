# Pre-Phase-3 boot and build verification

Phase 3 must **not** be started on the assumption that a successful file-layout check or an official 9front VM boot proves this repository's kernel is bootable.

## Verification gates (distinct evidence required)

| Gate | What it proves | Status before tests |
| --- | --- | --- |
| V0 — Source/history/license notices | Original upstream source and key license notices were imported without losing Git ancestry | PASS, from existing foundation CI |
| V1 — Official 9front VM smoke | A *separately distributed, prebuilt 9front release image* can run under QEMU | UNVERIFIED pending QEMU diagnostic results |
| V2 — Ryzova source native compile | The files at a recorded `Ryzova-Kernal` commit compile to a fresh AMD64 kernel with the correct 9front `mk` toolchain | NOT RUN |
| V3 — Boot freshly built kernel | The **V2 artifact** boots under QEMU with recoverable boot logs and matching checksum | NOT RUN |
| V4 — Basic runtime checks | Booted V3 kernel reaches user space and provides 9P, local storage, network, basic process/memory functions | NOT RUN |
| V5 — Physical hardware | The kernel works on explicitly listed hardware IDs / platforms | NOT RUN |

The diagnostic workflow [`prephase3-qemu.yml`](../.github/workflows/prephase3-qemu.yml) downloads **9front-11952.amd64.qcow2.gz** from the [official release archive](https://build.9front.org/release/), records the downloaded SHA256 and launches its **prebuilt** kernel in QEMU. This can at most satisfy V1. It must **never** be counted as a successful build/boot of Ryzova's repository source. If serial output does not show a definite 9front marker, the V1 job fails and records a screenshot for manual investigation.

### Unresolved reproducibility requirement

The official image is pinned by *release filename*, but its checksum was **not independently fixed prior to the first diagnostic run**. The SHA256 file collected in the job is provenance information, not independent security validation. Before adopting a release as a long-term CI build base, record and verify a trusted, reviewed SHA256 or signature in workflow code.

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
