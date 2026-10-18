<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M1 — Universal USB Class Driver Program

## Delivered in initial class-validation wave

Existing Ryzova/9front-derived user-space class implementations:
- USB HID boot keyboard and pointer: nusb/kb
- USB mass storage BOT and existing UAS interface handling: nusb/disk
- USB Audio Class 1 and 2: nusb/audio
- CDC Ethernet functions: nusb/ether

The new original portable nusb/lib/m1class.c and .h provide shared protocol
safety checks, linked into the USB library. Changes reject malformed device
descriptors and invalid SuperSpeed endpoint-0 sizes, defend HID read packet
sizes, reject insufficient USB Audio 1 sampling-rate descriptor bytes,
reject invalid 64-bit mass-storage capacity/block sizes, prevent unlimited
BOT mismatched status tags and invalid CDB lengths, and validate CDC Ethernet
MAC strings and zero max-packet cases.

Seven additional M0 registry entries match USB interfaces by exact
class/subclass/protocol. They remain source-candidate only, with no auto-bind
and no claim of verified device support.

## Compatibility preservation

- 17-byte legacy hub device descriptor exception remains accepted if its required fields are present.
- This wave does not replace USB drivers or alter existing native PCI probe/attach paths.
- No vendor firmware, GPL-imported third-party driver source, new vendor IDs, or automatic USB controller claims are introduced.
- A USB class match is NOT evidence that a specific device model is compatible.
- Existing nusb user-space programs require native 9front/Ryzova toolchain build and physical device testing before release.

## Required M1 qualification (NOT DONE)

1. Native Plan 9 user-space nusb/lib, nusb/kb, nusb/disk, nusb/audio, nusb/ether builds, including application linking.
2. Modern AMD64 QEMU emulated USB HID, mass storage and USB network/device enumeration, detach/reconnect and fault injection.
3. Real devices: old and new keyboards/mice, BOT/UAS drives, USB Audio 1 and Audio 2 playback/capture, CDC ECM Ethernet and OS recovery.
4. Audio sample rates, SCSI sense/residue, firmware/permissions, suspend/resume, low-RAM legacy PC regressions, throughput and USB3 stress validation.
5. Explicit per-model qualification evidence and human approval. Until this happens, M1 universal hardware support is not complete.

The 1-million-device target is not a current support count.
