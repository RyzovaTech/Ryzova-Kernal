<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M2 — Intel / AMD / Realtek chipset family expansion

## Engineering deliverables: source integration, not certification

This stage adds 12 **exact PCI vendor/device source candidates** to the M0
read-only registry and regenerated native table. M2 prioritizes:
- Modern Intel desktop/server Ethernet and HDA controller candidates
- AMD desktop/laptop HDA candidates
- Realtek gigabit RTL8168/RTL8169 families (modern and legacy)
- Legacy Realtek RTL8139, AMD PCnet, Intel 82540EM
- Legacy Intel WPI Wi-Fi requiring independently reviewed firmware

These IDs are grounded in the **existing repository driver code**. They do NOT
mean these cards were physically tested. A source code match neither changes
which drivers attach at boot nor guarantees stable DMA, interrupts, firmware,
PHY negotiation, sound codecs, network throughput or suspend/resume.

Each entry in `ryzova/drivers/m2-chipset-families.json` references an exact
source anchor and release track. `scripts/m2_chipset_audit.py` verifies:
- The driver source explicitly contains the referenced PCI device ID
- The matching kernel driver module is enabled by pc64 configuration
- Matching registry rules, firmware metadata, and the C-native generated PCI
  candidate table remain consistent; duplicates/unknown source fail closed
- Intel, AMD and Realtek families plus modern and legacy AMD64 tracks survive
- Every new entry has certified=false and auto_bind_allowed=false

Portable C PCI matcher tests exercise all 12 exact IDs over 256 revision codes
per selector (3,072 synthetic lookups), class fallback and ambiguous matches.
These do not represent 3,072 additional hardware models.

## Evidence and release blockers

M2 Source/Build Stage: actual CI compilation and native AMD64 QEMU boot are
required before review. The native test uses two separate boots: the first
preserves normal VirtIO networking, 9P and storage; the second adds emulated
AMD PCnet and RTL8139 PCI NICs **only** to read #P/drivercandidates. It
records both original vendor/device IDs and candidate labels without claiming
successful NIC traffic. Full serial evidence is archived by GitHub Actions. The M0 native #P/drivercandidates file is still
read-only. Existing proprietary firmware is never included or licensed by a
registry entry.

For M2 **hardware completion**, require at least:
1. Hardware model and revision logs, PCI discovery, attach/detach and reset.
2. Functional read/write or live traffic; DMA and IRQ teardown validation.
3. Ethernet link negotiation, packet integrity, high-load and suspend/recover.
4. HDA speaker/microphone codec initialization and output/input functionality.
5. Intel WPI firmware checksum, source and legal redistribution clearance;
   authenticated association and reconnect; fallback with no firmware.
6. Two real AMD64 tracks: 2020–2026 Intel/AMD devices, plus older/lower-RAM
   machines with legacy PCI / SATA / Realtek / AMD PCnet hardware.
7. Per-model evidence and independent maintainer human approval; **never**
   count aliases, broad class matches or synthetic revisions as certified.

All family records remain `source-candidate`. Release qualification is
**BLOCKED**, and 1,000,000 hardware models are not claimed.
