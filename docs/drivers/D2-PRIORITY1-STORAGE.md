<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D2 Priority 1 — NVMe / VirtIO storage source hardening

- NVMe: reject zero sector size or a transfer window smaller than one sector instead of looping with zero progress.
- VirtIO 1.0 and legacy PCI block/SCSI: reject invalid completion head IDs, out-of-range descriptor chain links and chains without a terminator before dereferencing waiter/free-list arrays.
- AHCI reviewed; recovery paths remain pending validation. No AHCI behavioral changes in this patch.
- Static regression checks only. Native AMD64 build, QEMU destructive/interrupt/recovery testing and physical hardware qualification must be completed before release.
- Malformed completion records are currently dropped without controller reset; outstanding I/O may wait indefinitely. Full reset/error propagation remains an open task.
