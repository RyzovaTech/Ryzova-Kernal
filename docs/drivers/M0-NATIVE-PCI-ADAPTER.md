<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M0 Native AMD64 source-candidate adapter

This is **real kernel linkage of the source-only candidate selector**, not hardware driver support.

## Runtime entry point

The AMD64 `pc64` build links `ryzovadrvmatch.c` and `ryzovadrvprobe.c`.
After `pcicfginit()`, the boot code registers `#P/drivercandidates` as a
read-only architecture diagnostic. On a booted Ryzova guest, read:

    cat '#P/drivercandidates'

The file is generated on demand from existing `Pcidev` records using
`pcimatch()` without reconfiguring or attaching anything. It prints a bounded
list of source candidates (max 24 rows from up to 512 enumerated PCI
functions) and truthful summary counters. If the cap is hit, output states
`capped=1`; a PCI class match is **not** a proof that a driver works. Modern
NVMe, AHCI, xHCI, HDA and a single Intel i225 ID are the five deliberately
small initial PCI selectors. Source candidates for Bluetooth USB interfaces
remain **host inventory only**.

## Rules and audit policy

`scripts/m0_native_rules.py` converts only validated PCI M0 registry rules into
`sys/src/9/port/ryzovapcirules.h` deterministically. Every source change must
pass `python3 scripts/m0_native_rules.py --check`; no unreviewed IDs, runtime
enable flags or firmware payloads may be silently imported.

The legacy 9front-derived `pcimatch()` device probes, PCI scan logic, DMA
mapping and IRQ initialization are unchanged. The new architecture file does
not use `pcicfgw`, BAR memory mapping, bus-master enable, device reset or
interrupt handlers. It must remain a read-only observability adapter unless
a separately reviewed and hardware-tested driver-binding API is added.

## Verification and missing evidence

- Unit/regression workflow: `m0-native-pci.yml` verifies registry parity,
  portable C selector behavior, and source-side read-only invariants.
- The repository's existing experimental Phase 3 native AMD64 QEMU build
  verifies compilation/linkage of the `pc64` image. It does **not**
  automatically certify that reading `#P/drivercandidates` worked in the
  guest; that runtime check requires a captured serial or device log.
- Real modern/legacy AMD64 PCI hardware enumeration, hotplug, power,
  physical DMA/IRQ safety, performance and manufacturer/firmware
  qualification remain unverified.
- No automatic driver binding, new PCI device compatibility, million-device
  production registry, USB native enumeration, or GPU acceleration is claimed.

## Next implementation boundary

Create native PCI/USB enumeration snapshot APIs and a separately reviewed
family attach lifecycle with explicit DMA/IRQ/error recovery gates. Do not
tie `source-candidate` results directly to `pcienable()` or DMA until tests on
both new and older PCs verify safe operation.
