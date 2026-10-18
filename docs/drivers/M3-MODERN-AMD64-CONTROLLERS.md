<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M3 — Modern AMD64 Controller Safety (engineering milestone)

## Deliverables

This M3 wave hardens **real existing Ryzova native kernel drivers** rather
than adding unsupported PCI device IDs to inflate the 1-million-driver goal.

**Intel X550/X553 10GbE:** replaces previously unbounded NVM/DMA readiness
and RX queue enable loops with bounded polls (at most 1000 iterations of
1 ms, aborting on an all-ones vanished-device register). It checks the
controller MMIO BAR has room for all registers used in reset and that MSI-X
BAR is nonempty before mapping. Failed reset disables the PCI device before
unmapping it. The existing PCI match and support scope are unchanged.

**NVMe class storage:** verifies a nonzero memory BAR with at least the
doorbell base, and checks the CAP.DSTRD-advertised admin SQ/CQ doorbell
registers fit inside the mapped BAR before interrupt-mask writes. A failing
controller is unmapped and disabled without continuing to start DMA.

## Independent engineering evidence

Run:
- \`python3 -m unittest discover -s tests -p 'test_m3_modern_controllers.py' -v\`
- Repository M0/M1/M2 candidate and release gates
- Fresh native Plan 9 AMD64 \`6c\`/\`6l\` kernel build, QEMU boot,
  9P/storage/network/PCI read-only diagnostics
- Modern and legacy AMD64 release qualification as distinct evidence tracks

## Safety boundaries

A successful source build proves the patched drivers compile and preserve
a bootable system under existing QEMU virtual hardware. It does **not**
prove actual Intel X550 Ethernet traffic, hotplug/recovery or physical NVMe
read/write operation, data integrity, power management, or vendor firmware
qualification. No new hardware model is certified; no vendor IDs, automatic
bindings, external driver source, firmware payloads or 9front auto-sync are
added. Existing legacy network and storage drivers are not replaced.

**M3 real-hardware certification: BLOCKED** until both modern and legacy
hardware lab evidence and human-reviewed release gates are satisfied.
