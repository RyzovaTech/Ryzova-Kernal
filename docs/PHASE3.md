# Ryzova Kernel Phase 3 — implementation evidence and gates

## Target milestones

- **3.0:** Source-based native AMD64 `mk` and new-kernel QEMU boot, including the native `rc` shell.
- **3.1:** Ryzova Kernel identity, versioning and origin attribution.
- **3.2:** Read-only native Plan 9 device interface, no new syscall ABI.
- **3.3:** Machine-readable AMD64 build profile for future downstream OS variants.
- **3.4:** CI provenance, native QEMU compile+boot regression and identity checks.
- **3.5:** Developer preview artifacts if the above pass and redistribution/legal gates allow publication.

## Verified Phase 3.0 foundation

The [native AMD64 build / fresh boot workflow](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38698937438) uses the checked-out `sys/src/9`, `sys/include` and `amd64/include` source archive in an isolated 9front VM. It builds `9pc64` with native `mk`, installs it onto the guest's 9fat boot partition, verifies with `cmp`, restarts QEMU, and executes a user-space `rc` command after fresh boot.

The pristine 9front release VM was an isolated **toolchain bootstrap environment**, not the kernel whose second-boot success was checked.

## Phase 3.1–3.4 evidence — verified

The [fresh source-build and identity CI run](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38703531423) succeeded with Ryzova native `mk`, `9pc64` installed onto the QEMU guest's FAT boot partition, byte-for-byte `cmp`, a second QEMU boot, and native `rc` output:

- `#Z/version`: `Ryzova Kernel 0.1.0-dev`.
- `#Z/foundation`: `9front-derived`.
- `#Z/abi`: `experimental-0`.
- `#Z/version` rejects a write with `permission denied` and remains readable afterward.
- Minimal `/proc` and `/net` existence checks plus per-process namespace `bind` succeeded.
- The workflow now archives fresh-boot serial and host diagnostics for review and reruns when kernel source or Ryzova metadata changes.

**These are minimal smoke tests, not comprehensive 9P/network/storage regression checks or real hardware certification.** The compilation source archive SHA256 is recorded, while separate release-grade independent kernel binary checksum/export and full regression testing remain to be completed.

## Release policy

This phase does not waive [legal issue #3](https://github.com/RyzovaTech/Ryzova-Kernal/issues/3): inherited 9front package assets have license exceptions. The repository is public, but **no all-inclusive redistributable RyzovaOS image** is approved by a green CI run. The AGPLv3-marked Ryzova component is separately licensed and does not change upstream rights.
