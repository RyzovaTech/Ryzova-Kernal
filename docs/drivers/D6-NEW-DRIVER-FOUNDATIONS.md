<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D6 — Experimental new driver foundations (not hardware-certified)

## Bluetooth: new opt-in nusb/bt utility

Original, independently written USB HCI event diagnostic under
sys/src/cmd/nusb/bt/. The program looks for interface class/subclass/protocol
E0/01/01 and an IN interrupt endpoint. It opens an endpoint and reads a bounded
number of complete HCI events, reporting event types and bytes. The optional
**explicit** -r flag sends only HCI_Reset (0x0c03) over a standard class
control transfer. It does **not** auto-bind or auto-send controller commands.

When built in a 9front/Ryzova userland, run manually:
nusb/bt [-r] [-n 1] <usb-device-id>

**Not implemented:** Bluetooth initialization/host stack, pairing, bonding,
inquiry, LE scanning, security/encryption, ACL/SCO/ISO channels, controller
firmware installation, detach/recovery, or persistence. No physical USB radio
was available for verification. This command is an opt-in diagnostic first
step, **not** full Bluetooth hardware support.

## GPU: new VirtIO-GPU wire-format helpers, unlinked

Original GPU 2D request builders (sys/src/9/port/virtgpuwire.c and .h) for
GetDisplayInfo and Create2D. They produce little-endian command bytes according
to the OASIS VirtIO GPU Device specification, with a conservative prototype
dimension cap. **Not linked** in pc64; no PCI attachment, virtqueue transport,
DMA backing, IRQ handling, scanout, display mode, accelerated rendering,
3D stack, or runtime GPU support has been added.

The next GPU work requires device ID 16 (VirtIO-GPU), queue 0 control and
queue 1 cursor support, interrupts, resource backing, teardown and QEMU
display verification before even claiming experimental 2D output.

## Sources and licensing

Specification references (not source copied from Linux drivers):
- Bluetooth Core HCI USB transport:
  https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core_v6.3/out/en/host-controller-interface/usb-transport-layer.html
- USB-IF E0/01/01 class:
  https://www.usb.org/defined-class-codes
- OASIS VirtIO GPU device:
  https://github.com/oasis-tcs/virtio-spec/blob/master/device-types/gpu/description.tex

## Validation limitations and release gates

Portable C wire-format tests run via GCC in CI. Python source checks ensure
Bluetooth stays opt-in and the GPU helper remains unlinked. These tests do NOT
compile the 9front-specific nusb/bt binding itself, boot QEMU, enumerate a
Bluetooth dongle, or verify real GPU display hardware. Before promotion,
require Plan 9 native toolchain build, QEMU or USB emulation, fault injection,
physical device logs, firmware/legal review and independent maintainer signoff.
No release gate has been relaxed.
