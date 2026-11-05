<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M5 Closure Attempt to M6 Entry

## Completed source engineering

M5 ARM64 PCIe ECAM arithmetic validation, ARM64 PCI interrupt callback guards,
the ARM64/modern AMD64/legacy AMD64 server matrix and source test suites
were integrated into main in PR #46. The 9front native ARM64 7c compiler
compiled the Ryzova ECAM helper in the pinned AMD64 CI guest. Source-level
proof does not certify operational ARM64 hardware.

## ARM64 full build blocker and corrective attempt

The first native ARM64 9qemu build failed because the AMD64-only
9front CI guest lacked /arm64/bin/paqfs. This follow-up CI attempts to:
1. Compile both the ECAM validator AND actual ARM64 PCI port using 7c.
2. Build the ARM64 paqfs and auth/factotum executables from checked-out source.
3. Install the userspace prerequisites in the isolated, disposable guest.
4. Retry the full ARM64 9qemu kernel and record what remains missing.

Each check is recorded independently in the native M5 evidence artifact.
An ARM64 7c compile or even a 9qemu link is not an ARM64 QEMU boot.

## 2026-10-25 native CI evidence: missing ARM64 target libraries

PR #49 full native-build rerun https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/39900171436
completed GitHub Actions successfully, but the actual ARM64 `paqfs`,
`factotum`, `9qemu` linker and boot stages remained **blocked**.
Native `7c` compiled `m5ecam.c` and `pciqemu.c`; the guest-side linker
then failed with:

```text
7l -o 7.paqfs paqfs.7
??none??: cannot open file: /arm64/lib/libc.a
```

The same missing library blocked `factotum`. The kernel reported that
`/arm64/bin/paqfs` could not be made; the ARM64 QEMU probe correctly
reported `not-booted-native-link-incomplete`. AMD64 fresh native QEMU,
9P, TLS and storage/network regression tests passed on that runner.

### Independent cross-library bootstrap attempt

On the M5.5 branch, the native-build CI now transfers the repository's
exact `sys/src/libc`, `libmp`, `libsec`, `libip`, `libdraw`,
`libmemdraw`, `libmemlayer`, `libauth` and `libauthsrv` source
into the pinned, disposable 9front guest. Each ARM64 `mk install`
stage records the compiler result, then independently checks its
`/arm64/lib/<name>.a` output. Missing archive, incomplete `mk`,
missing serial marker or wrong install path blocks ARM64 linked status.

The resulting artifacts and native build logs must be inspected to
determine whether this succeeds and what the **next** blocker is.
A successful CI workflow by itself remains insufficient evidence of a
linked/booted ARM64 image or any real hardware certification.

## M6.1 exact-head ARM64 boot acceptance (strict and non-certifying)

The M5.5 PR now runs `scripts/m6_arm64_boot_acceptance.py` after the
existing AMD64 fresh-build, 9P/TLS and network/storage regression evidence.
On the M5.5 PR only, this check **fails the native CI job** if ARM64
libraries, native `paqfs`/`factotum`, kernel link, FAT copy, host-verified
SHA-256 or the actual AArch64 QEMU serial boot observation is missing.

The negative result is saved to
`artifacts/phase3/m6-arm64-boot-acceptance.json` and included in the
uploaded native evidence artifact even when CI fails. Synthetic Python
unit tests validate only that the evidence gate rejects bad/missing inputs;
they do not provide ARM64 hardware/runtime evidence. No automatic
9front sync, release authorization, driver ID certification or
unreviewed binary redistribution is performed.

This strict check is scoped to the M5.5 PR head ref so that independent
existing AMD64 / legacy QEMU builds and unrelated security branches
remain unaffected. When the gate passes, physical hardware certification
still remains zero and further ARM64 VirtIO, SMP/GIC/IRQ and DMA/IOMMU
functional verification is needed before a hardware release.

## M6 release policy

M6 *engineering planning* may start once M0-M5 source and safety changes
are integrated and all remaining blockers are enumerated.

M6 *functional or hardware release* remains BLOCKED until:
- Full reproducible 9qemu bootfs and ARM64 kernel build, SHA provenance
- Fresh ARM64 QEMU virt boot with actual serial evidence
- Actual ARM64 VirtIO network packets and block read/write integrity
- SMP, GIC interrupts, DMA and IOMMU fault containment tests
- Independent physical ARM64 server, modern AMD64, legacy AMD64 lab evidence

Neither QEMU PCI candidates nor host-source-only tests can certify physical
hardware. Newly physically certified model count stays zero pending audits.

## M6.2 experimental VirtIO functional I/O probe (2026-11-03)

The M5.5 native QEMU boot probe now optionally launches a **second isolated,
source-built AArch64 QEMU guest** with a VirtIO-net PCI device and
VirtIO-SCSI block controller after M6.1 image SHA + kernel boot are verified.

The test harness in `scripts/m6_arm64_virtio_probe.py` uses a transient
8 MiB raw disk, a bound `127.0.0.1` HTTP fixture and QEMU user-mode
networking with `restrict=on` plus one explicitly permitted
`guestfwd` endpoint (see QEMU user networking documentation).
The guest must reach a real shell before any commands are sent.
Network I/O is **not** accepted without both (a) a real HTTP request
received by the host fixture and (b) the matching guest SHA-256 digest
of the host payload. Storage I/O is **not** accepted without all of
(a) a completed guest write command, (b) guest SHA-256 of the exact
read-back bytes and (c) host-side verification that the disposable
VirtIO-SCSI disk actually contains the guest-written payload.

The independent artifact `artifacts/phase3/m6-arm64-virtio-probe.json`
and raw `m6-arm64-virtio-serial.log` are uploaded even when guest
userland is unavailable. Missing shell, network request, read-back,
host-side writes or hash evidence always reports **blocked**, never
a functional VirtIO pass. Synthetic unit tests check the evidence
adjudicator but do not certify hardware or real QEMU execution.

**Milestone boundary:** ARM64 kernel banner+cpu0 plus SHA-256-verified
uImage proves a QEMU boot, not shell/userland functionality, data-plane
networking, block integrity, DMA/IOMMU reliability, physical devices
or server release readiness. The M6.2 probe is research-only while
the corresponding actual guest observations remain incomplete.

## M6.2 exact-head functional I/O acceptance (strict draft-only gate)

`scripts/m6_arm64_virtio_acceptance.py` implements a separate, fail-closed
GitHub Actions check on the M5.5-owned PR. It accepts M6.2 only if the
**same checkout** has SHA-256-verified M6.1 kernel boot, verified uImage
digest in the second QEMU guest, a reachable guest shell, attached VirtIO
devices, a real host HTTP request matched to the guest's payload SHA-256,
and a guest block-write/read SHA-256 independently corroborated by the
host's ephemeral disk bytes. Zero physical models are certified.

This gate always writes
`artifacts/phase3/m6-arm64-virtio-acceptance.json`, returning nonzero
for missing or inconsistent evidence; its report is included in the
native guest CI artifacts even if the job fails. Synthetic tests
(`tests/test_m6_arm64_virtio_acceptance.py`) are contract tests,
**not** proof of functioning hardware or guest userland.

M6.1 boot remains independently accepted under its SHA-256 gate.
M6.2 requires real datapath evidence, which may remain blocked until
ARM64 userland boot, guest root filesystem and VirtIO enumeration work.
Neither CI nor this PR relaxes release or physical-hardware certification.

## 2026-11-05 verified ARM64 bootfs panic and native rc repair

Run https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41951866039
proved actual ARM64 kernel link and independent uImage SHA-256, but the
actual AArch64 guest serial also showed `panic: boot process died:
file does not exist: '/bin/rc'`. The separate VirtIO guest hit the same
panic. No ARM64 guest shell or network/storage I/O was verified.

Source-built ARM64 `rc` from the exact Git checkout now must be compiled
and installed into `/arm64/bin/rc` **before** the embedded bootfs is
repacked. Missing executable, native `mk` failures or standalone
nonzero completion markers block the ARM64 native linker-evidence gate.
The M6.1/M6.2 CI acceptance reports explicitly reject an ARM64 QEMU
boot panic, even when the Plan 9 banner and cpu0 text were printed.
This repairs prior false-positive boot qualification; kernel proof and
functional data-plane qualification are still separate. Zero physical
models are certified.

## 2026-11-05 native ARM64 bootrc command repair

The last exact-head guest serial in run
https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41953538116
proved source-built rc, but ARM64 echo, test, sed, bind and other bootfs
commands were absent. The guest printed tens of thousands of repeated
bootrc command errors rather than a usable interactive recovery shell.

The native pinned-guest build now cross-builds 15 core ARM64 bootrc
utilities from the same checkout. The kernel link qualification now
requires each executable to be installed and verified, and rejects
missing reports. M6.2 uses the explicit Plan 9 bootargs `!rc` prompt
only for the research QEMU recovery shell, not for general boot success.
Real network and scratch disk I/O remain separate mandatory tests.

## M6.2 native userland networking tools

The QEMU ARM64 bootfs extends the original 9front bootfs proto with
source-built `ip/ipconfig`, `webfs`, `sha1sum`, and an exact-checkout
`/rc/bin/hget` script. These tools are built and installed through
actual ARM64 native 7c/7l and fail-closed provenance gates before the
embedded QEMU bootfs is linked. This is an experimental QEMU research
configuration, not hardware release qualification. Negative synthetic
contract tests must not be confused with actual HTTP and disk I/O.

## ARM64 native libregexp cross-link dependency (2026-11-05)

[Run #41958001641](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41958001641)
compiled fourteen of fifteen source-built bootrc core executables but failed
`7.sed` at `7l`: `cannot open file: /arm64/lib/libregexp.a`.
The native source archive now includes checked-out `sys/src/libregexp` and
builds/verifies its ARM64 archive **before** any bootrc tools and kernel
bootfs packaging. M6.1 acceptance also requires the library; no
kernel banner or source-only test can bypass this fail-closed gate.

## 2026-11-05 QEMU PL011 short-console-input RX interrupt repair

[Native M6.2 run #41959063374](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41959063374)\ncompiled all 17 bootstrap libraries and an ARM64 QEMU kernel with the embedded\nbootfs. Source-built kernel boot and SHA verification passed, but the second\nAArch64 guest repeatedly printed the `bootargs is` prompt while the host\nprobe had sent the short `!rc\\r` recovery-shell input. No guest-side HTTP,\nshell or block read/write evidence was obtained; M6.2 failed as required.\n\nThe PL011 driver enabled FIFO (`FEN`) and RX threshold interrupt\n(`RXIM`) but not receive-timeout interrupt (`RTIM`, bit 6). Short input\nmay remain below the FIFO trigger threshold. The experimental ARM64 QEMU\nconsole enables RX timeout as well, retaining the existing receive-drain\nand ICR acknowledgement logic. The QEMU scratch-disk SHA step now pipes\nread-back bytes directly into the digest command, without writing to\na possibly read-only embedded `/tmp`. This is a hypothesis-driven device\nfix pending actual fresh native QEMU serial and functional-I/O proof.\n