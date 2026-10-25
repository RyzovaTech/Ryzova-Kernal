<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# M5 Closure Attempt to M6 Entry

## Completed source engineering

M5 ARM64 PCIe ECAM arithmetic validation, ARM64 PCI interrupt callback guards,
the ARM64/modern AMD64/legacy AMD64 server matrix and source test suites
were integrated into main in PR #46. The 9front native ARM64 7c compiler
compiled the Ryzova ECAM helper in the pinned AMD64 CI guest. Source-level
proof does not certify operational ARM64 hardware.

## ARM64 full build blocker and corrective attempt

The first native ARM64 9qemu build failed because the AMD64-only
9front CI guest lacked /arm64/bin/paqfs. This follow-up CI attempts to:
1. Compile both the ECAM validator AND actual ARM64 PCI port using 7c.
2. Build the ARM64 paqfs and auth/factotum executables from checked-out source.
3. Install the userspace prerequisites in the isolated, disposable guest.
4. Retry the full ARM64 9qemu kernel and record what remains missing.

Each check is recorded independently in the native M5 evidence artifact.
An ARM64 7c compile or even a 9qemu link is not an ARM64 QEMU boot.

## 2026-10-25 native CI evidence: missing ARM64 target libraries

PR #49 full native-build rerun https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/39900171436
completed GitHub Actions successfully, but the actual ARM64 `paqfs`,
`factotum`, `9qemu` linker and boot stages remained **blocked**.
Native `7c` compiled `m5ecam.c` and `pciqemu.c`; the guest-side linker
then failed with:

```text
7l -o 7.paqfs paqfs.7
??none??: cannot open file: /arm64/lib/libc.a
```

The same missing library blocked `factotum`. The kernel reported that
`/arm64/bin/paqfs` could not be made; the ARM64 QEMU probe correctly
reported `not-booted-native-link-incomplete`. AMD64 fresh native QEMU,
9P, TLS and storage/network regression tests passed on that runner.

### Independent cross-library bootstrap attempt

On the M5.5 branch, the native-build CI now transfers the repository's
exact `sys/src/libc`, `libmp`, `libsec`, `libip`, `libdraw`,
`libmemdraw`, `libmemlayer`, `libauth` and `libauthsrv` source
into the pinned, disposable 9front guest. Each ARM64 `mk install`
stage records the compiler result, then independently checks its
`/arm64/lib/<name>.a` output. Missing archive, incomplete `mk`,
missing serial marker or wrong install path blocks ARM64 linked status.

The resulting artifacts and native build logs must be inspected to
determine whether this succeeds and what the **next** blocker is.
A successful CI workflow by itself remains insufficient evidence of a
linked/booted ARM64 image or any real hardware certification.

## M6 release policy

M6 *engineering planning* may start once M0-M5 source and safety changes
are integrated and all remaining blockers are enumerated.

M6 *functional or hardware release* remains BLOCKED until:
- Full reproducible 9qemu bootfs and ARM64 kernel build, SHA provenance
- Fresh ARM64 QEMU virt boot with actual serial evidence
- Actual ARM64 VirtIO network packets and block read/write integrity
- SMP, GIC interrupts, DMA and IOMMU fault containment tests
- Independent physical ARM64 server, modern AMD64, legacy AMD64 lab evidence

Neither QEMU PCI candidates nor host-source-only tests can certify physical
hardware. Newly physically certified model count stays zero pending audits.
