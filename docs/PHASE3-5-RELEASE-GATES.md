# Phase 3.5 — AMD64 developer-preview release gate

**Status:** the defined experimental QEMU technical gates passed in [CI run #38708363099](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38708363099). **Public binary release remains on hold** until scoped redistribution rights and maintainer approval are documented. This plan is not itself a license or legal clearance.

## Artifact provenance

The experimental QEMU workflow uses native 9front `mk` inside a temporary guest, built from the checked-out Ryzova source revision. For the test:
1. Build `sys/src/9/pc64/9pc64`, transfer to `/n/9fat/9pc64`, and compare with `cmp`.
2. Produce guest SHA256 digests of **both** the compiled and installed files.
3. Reboot into the installed file; verify fresh-boot `rc`, `#Z` metadata and native services.
4. On the host, convert the QEMU overlay to a sparse raw disk, locate its FAT 9fat partition and extract `/9pc64` with mtools.
5. Verify a host-computed SHA256 of the independently extracted file exactly matches both guest SHA256 digests.
6. Upload only `kernel-provenance.json`, `9pc64.sha256`, source revision, and logs; **delete the compiled binary before public artifact upload**.

Hash equality is integrity/reproducibility evidence, **not** a digital signature, identity assertion or third-party relicensing authority. A trusted upstream image digest is pinned for repeatability, but is not independently authenticated by a signed publisher attestation.

## Runtime gates

The fresh source-built kernel must reach native `rc` and pass:
- Identity paths `#Z/version`, `#Z/foundation` and `#Z/abi`; deny writes while allowing subsequent reads.
- Basic `/proc`, `/net` access and per-process namespace bind.
- Mount a separate `ramfs` **9P server** and successfully create/read a file.
- Mount `9fat` and read its active `plan9.ini` bootfile setting.
- Fetch a known payload via HTTP from the test host over QEMU VirtIO networking.

These are **functional regression smoke checks**, not exhaustive fuzz, network security, hardware performance or filesystem durability testing.

## Release prerequisites

- [x] CI passed; guest/host SHA256 and provenance were generated, extracted and cross-checked in run #38708363099. This is technical integrity evidence, not publisher attestation or legal clearance.
- [ ] Scoped inventory of material actually embedded in the 9pc64 binary and accompanying release assets is reviewed by a responsible rights-holder/counsel (see [legal gate #3](https://github.com/RyzovaTech/Ryzova-Kernal/issues/3)).
- [ ] Any restricted third-party material is removed, replaced with appropriate permission, or excluded from distributed assets.
- [ ] A valid authorized sign-off documents **what artifact may be redistributed under which license(s)**.
- [ ] Release notes disclose exact source SHA, upstream commit, pinned guest image hash, kernel hash, experimental ABI, unsupported hardware and known security limitations.
- [ ] Maintainer separately authorizes publication and tagged prerelease; verify an external contributor can reproduce tests.
- [ ] Keep kernel-only developer preview distinct from the future RyzovaOS distribution.

Do **not** claim that project-wide AGPL applies to inherited MIT or third-party files. Commercial licenses can be offered only for components Ryzova controls; AGPL itself permits compliant commercial usage.

## Current project identity

`Ryzova Kernel 0.1.0-dev`, `9front-derived`, `experimental-0` is a **developer identifier**, not a signed release version or API-stability promise.
