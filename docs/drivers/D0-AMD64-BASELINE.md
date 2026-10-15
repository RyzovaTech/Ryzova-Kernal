<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D0 — AMD64 driver baseline and qualification plan

**Scope:** Ryzova Kernel driver engineering only. No kernel, driver, scheduler, ABI, licensing-policy or upstream-sync changes are authorized by this report.

**Inspected branch:** `main` at `d6b1f3d8e78470f5ae9caf42d85deb983239e752` (2026-10-15).

**Important:** A source file, configured link entry, successful compilation or successful QEMU smoke test **does not certify support for a physical device**. All support statements below are *source/configuration observations*, not a tested hardware compatibility list.

## 1. Source of truth

- The AMD64 configuration is [`sys/src/9/pc64/pc64`](../../sys/src/9/pc64/pc64); it determines which driver modules are selected for the current 9pc64 build.
- AMD64 kernel build rules are [`sys/src/9/pc64/mkfile`](../../sys/src/9/pc64/mkfile).
- PCI/desktop-specific drivers primarily appear under [`sys/src/9/pc/`](../../sys/src/9/pc/).
- Portable kernel drivers and interfaces primarily appear under [`sys/src/9/port/`](../../sys/src/9/port/).
- The active native-build workflow is [`.github/workflows/phase3-native-build.yml`](../../.github/workflows/phase3-native-build.yml); its QEMU results do not replace physical-device testing.
- The [upstream policy](../UPSTREAM.md) states that automatic 9front source synchronization is retired; historical `upstream/front` is retained. This plan never re-enables automatic upstream merges.

## 2. First-pass inventory (configured in pc64)

| Family | Evidence in current configuration / source | D0 status |
|---|---|---|
| NVMe | `sdnvme` in `misc`; `port/sdnvme.c` | Linked/configured; no physical-device qualification evidenced |
| SATA / AHCI | `sdiahci` in `misc`; `pc/sdiahci.c` | Linked/configured; physical qualification pending |
| VirtIO block/storage | `sdvirtio`, `sdvirtio10` in `misc` | Linked/configured; QEMU-focused validation should be extended |
| USB host controllers | `usbuhci`, `usbohci`, `usbehci`, `usbxhcipci` in `link` | Linked/configured; USB devices/topologies unqualified |
| Ethernet | `ether8169`, `ether82563`, `ether82598`, `etherx550`, `etheri225`, `etherigbe`, `ethervirtio`, `ethervirtio10`, others in `link` | Families present; device-ID and real-hardware matrix pending |
| Wi-Fi | `etheriwl`, `etherwpi`, `etherrt2860` in `link` | Selected historical driver families; modern chipset/firmware coverage unknown |
| Audio | `audiohda` in `link` | HDA driver included; codec/device coverage unqualified |
| Display | `vgasoft`, `vgaigfx`, `vgaradeon`, `vgavesa` in `misc` | Display paths configured; **not evidence of modern GPU acceleration** |
| Platform and peripheral | `archacpi`, `pci`, `uartpci`, `pmmc`, `devkbd`, `mouse` entries | Baseline platform hooks included; power/suspend/peripheral matrix pending |

**Nuance:** Some drivers exist in `sys/src/9/pc/` but are commented out in `pc64`. Others are configured but probe only specific PCI IDs. Do not count either category as verified device support. The `pc64` file should be parsed with its section semantics (`dev`, `link`, `misc`, `ip`, `port`) before compiling an exhaustive module list.

## 3. Verification already available (not new driver certification)

- [`README.md`](../../README.md) and [`docs/PHASE3-5-RELEASE-GATES.md`](../PHASE3-5-RELEASE-GATES.md) document source-built AMD64/QEMU runtime smoke tests, including VirtIO networking, 9P and namespace checks.
- The latest main-commit foundation and license-inventory workflows completed successfully at this baseline.
- This audit did **not** run an independent native kernel build, a device-ID enumeration, fault injection or real-hardware tests.
- The project's binary release gate remains closed pending separate licensing and maintainer approval.

## 4. Mandatory next inventory step (D0.1)

Produce a reproducible device inventory with:

1. All configured and commented driver modules from `pc64`, alongside source paths.
2. Each driver's bus type, probe method, supported IDs/classes, firmware blobs and redistribution rules, where extractable.
3. Identification of overlapping drivers and probe ordering/conflicts.
4. Device/driver mapping records: vendor ID, device ID, subsystem ID, revision, firmware revision, tested kernel SHA.
5. Explicit status: **source-only**, **build-verified**, **VM-tested**, **physical-device-tested**, or **release-qualified**. Default to source-only until evidence exists.

Do not infer current laptop/GPU/Wi-Fi support from a driver filename alone.

## 5. Suggested implementation order

| Track | Proposed next work | Verification gate |
|---|---|---|
| D1 — infrastructure | Deterministic `pc64` config inventory and machine-readable hardware matrix | Parser fixtures + review, no kernel changes |
| D2 — Virtual devices | VirtIO block/network regression checks and device failure cases | QEMU boot, I/O integrity, network link/reset tests |
| D3 — storage | NVMe/AHCI controller-specific fixes selected from verified bug reports | Real device ID, read/write integrity, error recovery, repeated reboots |
| D4 — USB + wired LAN | xHCI/HID/USB storage and selected Intel/Realtek Ethernet revisions | Plug/unplug, transfer, fault/reset, DMA/interrupt tests |
| D5 — desktop/laptop | Audio, Wi-Fi/firmware, power and basic display | Physical hardware and suspend/resume where applicable |
| D6 — advanced graphics | GPU acceleration feasibility and firmware/legal audit | A separately defined GPU conformance/stability program |

Avoid committing arbitrary chipset IDs, DMA logic, firmware binaries or GPL-derived implementations before verified specifications, source-provenance review and test coverage.

## 6. Driver update safety contract

- Every change starts in a **driver-scoped branch/PR**, never a direct main-branch push.
- Preserve upstream attribution and inherited notices; new code is subject to the repository's file-level license/provenance process.
- Prefer original vendor specifications and public standards. Reading Linux implementation code does **not** automatically make rewritten code independently licensable; review derivative-work risks.
- For any driver change, require compilation, targeted tests, regression tests, and real-hardware qualification before labeling support production-ready.
- Keep last-known-good behavior and provide revertable commits. New probe IDs stay disabled or experimental until verified.
- Changing scheduler, core memory manager, general ABI or non-driver kernel architecture is outside this track and needs separate authorization.
- No automatic 9front updates, no upstream branch modifications and no public binaries are part of this report.

## 7. Recommended first follow-up PR

**D0.1 — machine-readable AMD64 driver inventory**, derived from `pc64` with tests, followed by a **D2 VirtIO reliability PR** after its exact QEMU/guest coverage is established.

This baseline is an evidence-led starting point, not a claim that new drivers have already been updated.
