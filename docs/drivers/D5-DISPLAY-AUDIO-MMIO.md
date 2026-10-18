<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D5 Graphics and Audio controller MMIO guards

- Intel integrated graphics: validate device/mapping presence, supported cursor pipe index and BAR0 register bounds before accessing backlight and cursor MMIO.
- Intel/other HDA: reject unassigned, zero-sized, or I/O BAR0 before mapping codec controller registers.
- This is safe probe/register hardening only; not full graphics acceleration or verified HDA sound.
- QEMU display/HDA, screen modes, backlight/cursor motion, audio playback/capture and real motherboard testing are pending.
