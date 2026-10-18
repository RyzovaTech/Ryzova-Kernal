<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M4 — Legacy AMD64 PC Preservation

## Scope

Preserve pre-2020 AMD64 desktops/laptops and low-resource computers rather
than abandoning them during Ryzova modern-driver development. This M4 source
and QEMU integration wave addresses concrete old PCI NIC safety defects.
It does not add i386/32-bit support and does not certify physical devices.

### Actual kernel driver changes

- AMD PCnet / 79C970: check PCI BAR0 really exposes at least the 32-byte I/O
  register range, does not overflow the 16-bit I/O port aperture, and is not
  zero before invoking ioalloc or inl/outl. Replace an unlimited CSR0
  initialization loop with a finite 1000 x 100 microsecond poll (100ms
  maximum), break early on missing 0xffff hardware or memory error, then
  quiesce the card, clear PCI bus mastering, disable PCI and release the
  controller's active flag on all early reset failures.
- Realtek RTL8139: reject IO-vs-MMIO BAR mismatches, truncated or
  16-bit-IO-address-space-overflowing BARs and base zero before the first
  port access. Keep existing reset/probe path for valid legacy devices.
- Neither change modifies M0/M2 PCI candidate matching, new-vendor IDs,
  proprietary firmware, or driver auto binding.

### Verification

1. M4 native source/static fault-path tests.
2. M4 policy audit preserves *both* modern and old AMD64 targets, including
   inherited SATA AHCI and EHCI USB 2.0 support requirements.
3. Full-memory QEMU/Plan 9 6c/6l native kernel build, guest boot,
   9P/storage/virtio networking regressions.
4. Independent AMD PCnet and Realtek RTL8139 PCI emulator boot with 384 MiB
   (versus the unchanged baseline guest's 2048 MiB). QEMU must find the
   exact two PCI candidate IDs and exit successfully. This is a reduced-RAM
   boot-and-discovery exercise, NOT full physical old-PC qualification.

### Qualification gaps

- Physical old AMD64 BIOS and UEFI boot, SATA/AHCI disk write integrity,
  EHCI USB 2.0 HID/disk operation and legacy Intel/Realtek/AMD NIC traffic.
- Low RAM measurements at 128/256 MiB, recoveries after hot-unplug and reset,
  network throughput and accurate physical firmware/PCI revisions.
- Independent human hardware release approval.

There are **0 newly certified physical models** in this patch. The
`ryzova/drivers/m4-legacy-qualification.json` release gate remains blocked
until actual evidence is supplied and independently reviewed. Passing the
384 MiB synthetic QEMU test is a source/build milestone only; the full M4
hardware certification milestone cannot honestly be called complete.

The 1,000,000-device goal remains aspirational.
