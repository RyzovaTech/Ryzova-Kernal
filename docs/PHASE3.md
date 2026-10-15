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

## Upcoming identity/runtime checks

- Verify `#Z/version`, `#Z/foundation`, `#Z/abi` in the **freshly built** kernel, not in the upstream release.
- Verify the device is read-only; report errors for writes to `#Z/version`.
- Verify existing `/proc`, `/net`, local disk and 9P operations were not regressed.
- Verify stable build provenance (checkout SHA, archive digest, installed bootfile compare, serial boot logs).

## Release policy

This phase does not waive [legal issue #3](https://github.com/RyzovaTech/Ryzova-Kernal/issues/3): inherited 9front package assets have license exceptions. The repository is public, but **no all-inclusive redistributable RyzovaOS image** is approved by a green CI run. The AGPLv3-marked Ryzova component is separately licensed and does not change upstream rights.
