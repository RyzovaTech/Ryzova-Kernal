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
