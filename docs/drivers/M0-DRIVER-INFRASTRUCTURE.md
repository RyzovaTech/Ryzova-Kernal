<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M0 — Million Device Initiative: driver infrastructure

**M0.1 is a source-candidate research index, NOT a runtime kernel driver registry.** It does not claim any new model works. Existing D0 source inventory, D-series release evidence, physical-tests.json and fail-closed approval requirements remain authoritative.

## M0.1 delivered

- Machine-readable candidate registry (6 deliberately scoped research records): PCI NVMe, AHCI, xHCI, HDA class selectors, Intel i225 VID 8086/DID 15f3, and an opt-in USB Bluetooth HCI interface. PCI class and USB class matches are not a finite device model list.
- Indexed, host-side, exact vendor/device and class/subclass/protocol matching, with revision bounds. Exact ID beats class and explicit protocol beats wildcard. Unmatched IDs stay unknown.
- Strict validation: known source file must exist, candidate kernel module must be enabled in pc64, duplicate IDs and overlapping revision ranges are rejected, invalid JSON/paths rejected, firmware references must exist.
- Firmware manifest metadata includes a WPI runtime path reference with license, digest and redistribution **not reviewed**. No firmware binary is added or distributed by this change.
- Registry schema hard-rejects any claim above source-candidate and any attempt to enable automatic binding. The output always includes hardware_verified=false and auto_bind_allowed=false.
- 8 tests including a synthetic 10,000-rule stress fixture. **Synthetic test rules are NOT supported devices**. The GitHub Actions job verifies M0 itself and existing D0 inventory tests.

## Commands

    python3 scripts/m0_device_registry.py
    python3 scripts/m0_device_registry.py --match pci --vendor 8086 --device 15f3 --classcode 02 --subclass 00 --protocol 00 --revision 01
    python3 -m unittest discover -s tests -p 'test_m0_device_registry.py' -v

These commands report an *unverified candidate*; they do not probe the NIC.

## M0.2–M0.5 implementation now available for review (source/prototype only)

- **M0.2 Linux sysfs discovery collector:** `scripts/m0_discovery.py --sysfs-root /sys` collects bounded, read-only PCI and USB device/interface snapshots and uses M0.1 matching to label unverified source candidates. This is a host-side development tool, **not** native Ryzova discovery. It records no serial numbers, certifies nothing, and makes no device changes. Only synthetic fixtures have been tested so far.
- **M0.3 driver family API candidate:** `sys/src/9/port/ryzovadrvmatch.[ch]` is a portable C exact/class/revision matcher, tested with GCC. **It is deliberately not linked to pc64**, and it does not do PCI/USB enumeration, MMIO, IRQ, DMA, or driver binding.
- **M0.4 safety gates:** `m0-safety-contract.json` and `scripts/m0_safety_gate.py` explicitly block firmware, DMA, interrupt and recovery readiness. Source audits never self-promote into physical release approvals.
- **M0.5 modern and old PC qualification:** `m0-qualification-plan.json` and `scripts/m0_qualification.py` require BOTH modern AMD64 and legacy AMD64 lab qualification tracks; report zero hardware certifications until independently reviewed evidence is available.
- **CI:** `m0-phases2-5.yml` compiles the experimental family selector, runs synthetic PCI/USB fixture tests, and ensures safety/qualification release remains blocked.

### Still required before calling these stages complete

1. Native Ryzova PCI/USB enumeration adapter, modern and legacy device tests, real signed/attested provenance and no runtime binding without review.
2. Plan 9 compiler integration for portable C API, bounded DMA and IOMMU mapping, IRQ teardown, firmware validation and controlled error recovery.
3. Repeatable QEMU boot/error injection plus physical modern and legacy PC hardware tests with independent human approval.
4. End-to-end support metrics, device/driver collision handling, profiling on low-RAM legacy machines and firmware redistribution clearance.
5. M0.6 million-scale compact runtime index, fuzzing and later ARM64/server adapters.

## Accurate scale accounting

Maintain separate counts of discovered device IDs, source-matched candidates, successfully attached devices, I/O-tested models, physically lab-verified models and release-certified models. Only physical/human evidence can support the latter claims. Never treat an alias, a PCI class wildcard, a database row or a synthetic test fixture as a verified device. The 1,000,000 number remains a long-term ambition, not a current count.

## Licensing boundary

Source is independently authored for Ryzova; Linux/vendor specs may be reference material subject to rights review. 9front auto-sync stays disabled. No new firmware payloads, kernel auto-binding, GPU acceleration or Bluetooth pairing are introduced here.
