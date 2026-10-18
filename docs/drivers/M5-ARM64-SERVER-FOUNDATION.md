<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M5 — ARM64 and Server Expansion: Foundation

## Existing starting point

The 9front-derived ARM64 QEMU kernel configuration already includes PCI,
VirtIO storage/network, and xHCI source. This is NOT verified Ryzova ARM64
boot support: earlier QEMU build evidence is for AMD64 only.

## M5.0 delivered

The ARM64 QEMU PCI ECAM mapping is 16 MiB at 0x3f000000. Previously the
config-space accessor calculated pointers without checking bus/window
boundaries or failed mappings. New m5ecam.[ch] implements portable,
side-effect-free validation for 16 buses, 32 devices, 8 functions, 4 KiB
config space each, and aligned 1-, 2- or 4-byte accesses. Out-of-window
configuration requests are rejected before touching MMIO. A failed vmap()
blocks PCI setup, and *pcimaxdno is clamped to 1..32.

The ARM64 kernel mkfile includes the helper. Portable GCC and Clang builds
plus adversarial unit vectors validate arithmetic, not the native ARM64
toolchain or an ARM64 kernel image. No native ARM64 build/boot is yet claimed.

## Platform matrix

- ARM64 QEMU/server: PCI, VirtIO network, VirtIO block, xHCI — source only.
- AMD64 server: NVMe, VirtIO storage/network, Intel X550, xHCI — prior
  AMD64 QEMU build/boot evidence, NOT physical vendor throughput or I/O.
- Legacy AMD64: PCnet, Realtek RTL8139, AHCI and EHCI retained as an
  explicit non-removable qualification track.

ryzova/drivers/m5-platform-matrix.json and scripts/m5_platform_audit.py
enforce evidence separation: fake ARM64 boots, hardware certification,
driver enablement and deleting legacy support are rejected.

## M5.1 — Cross-toolchain evidence and a discovered bootfs blocker

The native 9front AMD64 build guest has been used to **attempt** the ARM64
`mk 9qemu` target. The initial native target build failed, correctly, at
the bootfs dependency `/arm64/bin/paqfs` (not installed in the AMD64
development guest), before it could link a kernel. This is not a C
compilation success and cannot be called an ARM64 boot.

The next run probes the genuine Plan 9 `7c` cross compiler on the new
`m5ecam.c` source, captures the outcome separately, and still attempts
the full build. The ARM64 result JSON records three distinct outcomes:
native cross-C compilation, full ARM64 kernel link, and ARM64 guest boot.
Never treat a portable GCC test, a source inventory or ARM64 tool presence
as a successful ARM64 guest boot.

## M5.2 — ARM64 VirtIO network / storage

The ARM64 QEMU kernel configuration already contains `ethervirtio10`
and `sdvirtio10`. No new VirtIO functional device support is claimed.
`scripts/m5_server_gates.py` requires separate verified ARM64 network
traffic and block data-integrity evidence; untrusted serial markers
alone cannot self-certify. Both functional gates remain blocked.

## M5.3 — Server IRQ / multicore fault containment

ARM64 PCI callback registration now refuses null handlers and duplicate
allocations, reports a full 32-slot vector table, and clears all callback
state when unregistering. This is an initial safety improvement, not
complete SMP concurrency, GIC, DMA, IOMMU, MSI-X, hotplug or power-management
qualification. A concurrent multithread IRQ teardown audit is required
before the server platform can ship.

## M5.4 — Modern server + legacy regression, M6 entry

`m5_server_gates.py` separates ARM64 native toolchain evidence, ARM64
VirtIO function, SMP/IRQ/DMA, AMD64 physical server evidence, and legacy
AMD64 preservation. M6 **planning** is allowed with explicit blockers;
M6 hardware release readiness is not approved. The M0–M4 regression
suite and legacy profiles remain intact.

## Remaining M5 requirements (not yet complete)

1. Build the ARM64 QEMU kernel using a native compatible 9front 7c/7l
   toolchain with toolchain and source provenance retained.
2. Fresh ARM64 QEMU virt boot with console, GIC, bounded ECAM,
   VirtIO network/storage and xHCI functional evidence.
3. Server multi-core, DMA/IOMMU, interrupt teardown, hotplug, resilience
   and storage integrity testing on ARM64 and AMD64.
4. Actual ARM64 boards and modern/legacy AMD64 PCs tested with independent
   human-reviewed evidence before any hardware support certification.

Newly certified hardware models: 0. M5 source foundation is in progress;
full M5 platform and server qualification is NOT complete.
No 9front automatic upstream sync, PCI auto-binding or firmware import.
