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

## Remaining M0 gates (not implemented in M0.1)

1. **M0.2 Real PCI/USB discovery snapshots** with bounded parsing, provenance SHA and exact device revisions; never confuse discovery with successful I/O.
2. **M0.3 Reviewed kernel family-driver API** and opt-in probe adapter; no class-wide automatic claiming or disruption of existing independent 9front-derived probe paths. Modern AMD64 first, existing old-PC support regression-protected.
3. **M0.4 Firmware/DMA/IRQ safety**: obtain legal rights, verify provenance/checksums, DMA isolation, reset and error propagation, safe disconnection.
4. **M0.5 Reliability validation**: QEMU, legacy-PC, real 2020–2026 Intel/AMD PCs, stress, hotplug, recovery, suspend/resume and human-reviewed hardware test records.
5. **M0.6 Million-scale runtime index**: compact read-only representation, bounded memory/lookup time, fuzz testing; later ARM64 and server adapters. This Python control-plane tool is NOT deployed in the kernel.

## Accurate scale accounting

Maintain separate counts of discovered device IDs, source-matched candidates, successfully attached devices, I/O-tested models, physically lab-verified models and release-certified models. Only physical/human evidence can support the latter claims. Never treat an alias, a PCI class wildcard, a database row or a synthetic test fixture as a verified device. The 1,000,000 number remains a long-term ambition, not a current count.

## Licensing boundary

Source is independently authored for Ryzova; Linux/vendor specs may be reference material subject to rights review. 9front auto-sync stays disabled. No new firmware payloads, kernel auto-binding, GPU acceleration or Bluetooth pairing are introduced here.
