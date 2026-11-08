# Ryzova Kernel

[![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](docs/RELEASE-NOTES-DRAFT.md) [![9front-derived](https://img.shields.io/badge/base-9front%20%2F%20Plan%209-blue)](https://9front.org/) [![Ryzova code policy: GPLv3](https://img.shields.io/badge/Ryzova%20code%20policy-GPLv3--only-blue)](LICENSE.md) [![Public kernel binary: not released](https://img.shields.io/badge/kernel%20binary-not%20released-lightgrey)](ryzova/release/amd64-preview-candidate.json)

**A New Life for a Forgotten Vision**

Ryzova Kernel is an **experimental 9front/Plan 9-derived kernel and systems-software research project**. It builds on namespaces, 9P, and Plan 9's resource-oriented design, while exploring native kernel interfaces, constrained application-compatibility environments, and authenticated remote resource services.

**Ryzova Kernel is not a finished RyzovaOS desktop distribution.** Its Linux, Windows, and macOS application environments are separate, bounded **software runtimes** developed alongside the 9front-derived kernel. They are not a claim that arbitrary applications from those operating systems run, nor that those operating systems have been reimplemented.

> **Current status (6 November 2026):** Native AMD64 kernel source builds and QEMU boots are demonstrated. Selected Linux ELF, Windows PE/Win32, and Intel/ARM64 macOS Mach-O workloads have experimental interpreter/runtime and native-guest evidence. Broader app compatibility, physical-hardware qualification, production security, release authorization, and an official public kernel binary remain **incomplete**.
>
> This summary was reviewed against `main` at [`e6e17d7`](https://github.com/RyzovaTech/Ryzova-Kernal/commit/e6e17d7feefb7b29df11f9dd07d4fa7f2e1aa596). Historical documents and CI receipts can refer to earlier commits or superseded stages; they are not blanket certification of current or future revisions.

## More than an upstream 9front rebuild

**9front/Plan 9 is Ryzova Kernel's starting architecture, not the complete scope or identity of the project.** Ryzova keeps upstream history, attribution, namespaces and 9P while developing an independent systems-engineering direction. It is **not** a renamed 9front ISO, a theme, a Linux distribution, or an already finished general-purpose replacement for Windows or macOS.

The following workstreams are distinct and should not be conflated:

1. **Native kernel and platform engineering.** Ryzova-specific kernel-facing code includes the read-only [`#Z` identity device](sys/src/9/port/devryzova.c), AMD64 native source-build integration, and [driver-related kernel sources](sys/src/9/port/). The underlying 9front kernel remains a substantial inherited foundation; user-space compatibility interpreters are not incorrectly described as kernel-native ABI support.
2. **Cross-platform application execution environments.** [Compact Linux](ryzova/compat/linux/), [Compact Windows](ryzova/compat/windows/), and [Compact macOS](ryzova/compat/macos/) are independently engineered, bounded loaders, interpreters, API/runtime adapters and launchers. Some selected unmodified ELF, PE and Mach-O workloads have native Ryzova-guest QEMU proof. This does **not** imply general Linux/Win32/Darwin application support, native execution of guest machine code, or a fully interchangeable OS ABI.
3. **The Plan 9 resource model as a design tool.** Per-process namespaces, 9P and file-oriented resource access are used to explore explicit application grants and remote services. The goal is to make resources and compatibility environments composable without assuming that every proposed namespace is already mounted or every adapter shares one finished interface.
4. **A larger distributed-systems direction.** The [unified resource architecture](docs/PHASE8-2-UNIFIED-RESOURCES.md) investigates a future logical environment spanning storage, bounded caching, compute, network, GPU and devices, with identity-aware admission, placement and failure isolation. Today this consists of scoped 9P/TLS and coordinator experiments—not a production cluster OS, transparent shared memory, or pooled physical local CPU/RAM.
5. **Driver and hardware foundations.** The [M-series and D-series driver work](docs/drivers/D-SERIES-RELEASE-GATES.md) covers PCI/device inventory, selected AMD64 controller/USB paths, safety regression tests and ARM64 server research. [Bluetooth HCI diagnostics and VirtIO-GPU wire-format helpers](docs/drivers/D6-NEW-DRIVER-FOUNDATIONS.md) are early, explicitly limited foundations—not verified end-to-end Bluetooth, 2D/3D GPU support or hardware certification.
6. **Evidence-driven development.** Source checks, native toolchain builds, QEMU boot/reboot checks, hash provenance, selected differential application tests and fail-closed release gates distinguish demonstrated engineering from plans. A green test is evidence for its named workload and source revision, not universal certification.

**Long-term direction:** a kernel/platform that independent developers could build operating-system variants and new interfaces on, including a potential RyzovaOS. A public, certified kernel release, finished desktop environment and complete cross-OS interoperability are *goals*, not present deliverables.

## Project status at a glance

| Area | Demonstrated / implemented | Not established |
| --- | --- | --- |
| **Native kernel (AMD64)** | Fresh 9front-toolchain `mk` build, source-built kernel boot in QEMU, native `rc`, read-only Ryzova `#Z/version` identity, 9P/ramfs, namespace and selected storage/network smoke tests | Production stability, arbitrary hardware, a stable ABI, a public binary release |
| **Compact Linux** | Native Plan 9 user-space AMD64 ELF interpreter/runtime, selected musl/BusyBox workloads, bounded process, memory, filesystem, threading and network features; source-built QEMU evidence | Full Linux V1 acceptance, arbitrary Linux binaries, complete Python/Git/GCC workflows, general POSIX or desktop compatibility |
| **Compact Windows** | Bounded AMD64 PE32+ loader/interpreter, selected Win32/CRT APIs and console/file fixtures, native AMD64 QEMU qualification of scoped W1–W6 profiles; further workload research | Complete Windows runtime, general third-party Windows applications, GUI/DirectX/.NET, physical-disk durability certification |
| **Compact macOS** | Bounded Intel and ARM64 Mach-O interpretation on the **AMD64 Ryzova QEMU guest**, including pinned upstream jq 1.8.1 workloads and selected SQLite 3.54.1 CLI/in-memory SQL tests | macOS itself, general app/Framework compatibility, native ARM64 Ryzova kernel boot, persistent SQLite/GUI workloads |
| **9P and remote resources** | Research services, guarded read-only 9P, native guest TLS test paths, authenticated gateway/peer experiments and isolated Linux-network-namespace transport tests | Production end-to-end identity/PKI, remote physical RAM expansion, additional local CPU cores, general distributed process migration |
| **Drivers and hardware** | AMD64 source inventory, selected QEMU driver checks, safety gates and ARM64 server/cross-build research | Certified physical devices, operational ARM64 kernel boot/I/O/SMP, production driver qualification |
| **Release** | Source code and CI evidence | Signed/cleared public kernel image, independent hardware/security/legal approval |

**Important distinction:** A compatible executable can run through a constrained interpreter in a Ryzova/9front user-space process without becoming a native Linux/Windows/macOS kernel process. The scope of each verified workload is defined by its own evidence and capability limits.

## Architecture and source layout

| Path | Role |
| --- | --- |
| [`sys/src/9/pc64/`](sys/src/9/pc64/) | Native AMD64 kernel build sources |
| [`sys/src/9/port/devryzova.c`](sys/src/9/port/devryzova.c) | Ryzova-specific read-only kernel identity device |
| [`ryzova/compat/linux/`](ryzova/compat/linux/) | Compact Linux ELF loader, instruction/runtime, syscall and native user-space integration |
| [`ryzova/compat/windows/`](ryzova/compat/windows/) | Compact Windows PE loader, bounded AMD64 runtime, Win32 services and native launcher |
| [`ryzova/compat/macos/`](ryzova/compat/macos/) | Mach-O loaders/interpreters and bounded native launcher |
| [`ryzova/compact/`](ryzova/compact/) | Declarative Compact environment contracts and finite acceptance plans |
| [`ryzova/remote/`](ryzova/remote/) | Experimental 9P, TLS, trust, cache, computation and multi-node services |
| [`ryzova/drivers/`](ryzova/drivers/) | Driver inventories, qualification matrices and research policy |
| [`scripts/`](scripts/) · [`tests/`](tests/) | Native QEMU harnesses, host-side checks, fault tests and evidence tooling |
| [`.github/workflows/`](.github/workflows/) | Build, compatibility, security, driver and release-gate CI |

This repository preserves the upstream 9front source tree and its original history, rather than replacing the system with a Linux-based kernel or a virtual machine distribution.

## Compatibility environments: what actually runs?

### Compact Linux

The Linux environment runs as an **AMD64 Plan 9/Ryzova user-space application** that interprets selected Linux ELF binaries and translates a bounded set of guest behavior. Research now extends beyond the original Phase 5 parser: selected static/dynamic musl paths, BusyBox tasks, process/threads, file grants and network operations have source and native-guest test coverage.

**Full Compact Linux V1 remains incomplete.** CLX-01 and CLX-02 are recorded as complete for their declared scopes; CLX-03 and the remaining named-target/budget acceptance gates are unfinished. Do not infer general Linux compatibility from passing test counts.

Read [Compact Linux status](docs/COMPACT-LINUX-STATUS.md), the [V1 acceptance plan](docs/COMPACT-LINUX-V1-PLAN.md), and [native subset documentation](docs/PHASE9-2-COMPACT-NATIVE.md).

### Compact Windows

The Windows environment is a **bounded AMD64 PE32+/Win64 interpreter and selected Win32/CRT service layer**, not Windows or Wine. Source-built AMD64 QEMU tests cover specified compiler-generated fixtures and native filesystem/resource operations; W6 records scoped qualification and explicit remaining hardware/release gates. Additional W7 workload research does not automatically broaden that guarantee.

Read [Windows V1 integration](docs/COMPACT-WINDOWS-V1-INTEGRATION.md), [W6 native qualification](docs/COMPACT-WINDOWS-W6.md), [W7 workload research](docs/COMPACT-WINDOWS-W7.md), and the [Windows V1 plan](docs/COMPACT-WINDOWS-V1-PLAN.md).

### Compact macOS

The macOS environment is a **bounded Mach-O interpreter/runtime**, with Intel x86_64 and Apple Silicon ARM64 **application binaries** executed by a Plan 9 user-space launcher in the source-built **AMD64** Ryzova QEMU guest. This is not an ARM64 Ryzova kernel boot or an Apple operating-system environment.

The selected, pinned reference workloads include upstream jq 1.8.1 and SQLite 3.54.1 CLI operations. SQLite qualification is limited to the documented version/short in-memory SQL cases; persistent files, extensions, general Darwin APIs and arbitrary applications are not certified.

Read [M8 jq qualification](docs/COMPACT-MACOS-M8.md), [M9 launcher](docs/COMPACT-MACOS-M9.md), and [M9.3 SQLite execution](docs/COMPACT-MACOS-M93.md).

## Native kernel and remote-resource research

The AMD64 development build uses Plan 9/9front tools and boots the kernel **compiled from this checkout**, rather than treating an unmodified upstream VM boot as proof of Ryzova code. Native QEMU checks include the `#Z/version` read-only device, userspace smoke tests, filesystem/network paths and source/kernel hash evidence. The development identity is `Ryzova Kernel 0.1.0-dev`.

Remote-resource work uses 9P-oriented read-only access, explicit grants, bounded pure jobs, TLS and fail-closed test fixtures. A tested guest-facing TLS 1.2 session and a separate gateway-to-peer TLS 1.3 session **must not be confused with production end-to-end mTLS**. Some later experiments authenticate a disposable guest client certificate to the ingress, but do not provide production credentials or per-user ACLs. Linux network-namespace experiments are **not independent physical machines**. No claim is made that remote hardware becomes shared local RAM or CPU.

Read [build evidence](docs/BUILD.md), [native 9P/TLS security limits](docs/PHASE7-NATIVE-TLS-SECURITY-STATUS.md), [guest identity research](docs/NATIVE-GUEST-IDENTITY.md), [Phase 8 multi-node tests](docs/PHASE8-2-MULTINODE-EXECUTION.md), and [ARM64 driver/hardware status](docs/drivers/M5-ARM64-SERVER-FOUNDATION.md).

## Building and testing

**Host-side checks and native kernel verification are different evidence types.** A successful Python/C test, parser audit or host-side interpreter run alone does not prove a feature works in the booted Ryzova kernel.

- **Source/layout sanity:** `sh scripts/verify-foundation.sh`.
- **Native AMD64 build:** on a supported 9front environment with the required native toolchain, follow [`docs/BUILD.md`](docs/BUILD.md) and `sys/src/9/pc64/mkfile`; the native build uses `mk`, **not GNU Make**.
- **Reproducible QEMU evidence:** inspect [`.github/workflows/phase3-native-build.yml`](.github/workflows/phase3-native-build.yml) and [`scripts/phase3-native-build.py`](scripts/phase3-native-build.py). Additional selected Windows/macOS and Linux checks use their own workflows and test harnesses.
- **Compatibility acceptance:** start with the environment-specific docs, exact pinned reference binaries, native logs, negative tests and recorded PR-head workflow results; do not substitute a local host success for native evidence.
- **CI:** [GitHub Actions](https://github.com/RyzovaTech/Ryzova-Kernal/actions). At the source snapshot cited above, 28 push-triggered workflow runs for that exact `main` SHA reported success. This is **CI evidence for those jobs**, not physical-hardware or public-release certification.

## Source provenance and branches

- **`main`** contains the imported 9front tree, retained original ancestry, reviewed Ryzova additions and validation infrastructure.
- **`upstream/front`** retains a historical 9front source reference. **Automatic upstream synchronization is disabled**; no automatic upstream source or driver merge is configured.
- **`integration/*`** branches may be used for reviewed integrations and independent upstream evaluations.

The original 9front history was imported at `a0806493926c04ce90d4e4a46961dec30a1054dd` through [PR #1](https://github.com/RyzovaTech/Ryzova-Kernal/pull/1). Upstream: [9front.org](https://9front.org/) · [9front source](https://git.9front.org/) · [GitHub mirror](https://github.com/9front/9front).

For the frozen earlier AMD64 development reference and recovery protocol, see [Phase 4.0 baseline](docs/PHASE4-0.md) and [`ryzova/baselines/amd64-phase4.0.json`](ryzova/baselines/amd64-phase4.0.json). Historical phase documents remain useful for reproducing *their own* snapshots; the old Phase 4.1 status is no longer the project's complete roadmap.

## Licensing and commercial use

**Current Ryzova licensing decision: GPL-3.0-only for new and eligible rights-controlled Ryzova code, without a separate proprietary relicensing program.** This decision does not relicense inherited 9front material: actual terms remain file/asset-specific.

- **Inherited 9front/Plan 9 content:** generally MIT-licensed **with important file/asset exceptions** and retained upstream notices. See [`lib/legal/NOTICE`](lib/legal/NOTICE) and [`LICENSE.md`](LICENSE.md).
- **Ryzova-owned licensing policy:** GPLv3-only is the chosen open-source license for rights-controlled Ryzova code going forward. Files already expressly marked `GPL-3.0-only` are offered on those terms, including compliant commercial use; see [GPLv3 text](LICENSES/GPL-3.0-only.txt).
- **2026-11-08 source migration:** 155 Ryzova-origin AGPL-marked source, test, build-script and tooling files were updated to `GPL-3.0-only` in the [GPLv3 migration audit](docs/GPLV3-MIGRATION-AUDIT.md). This is a file-level outbound offer for those revisions, not a claim of legal certification, rights in third-party assets, or a retroactive cancellation of historical AGPLv3 grants. The [license inventory](scripts/audit_licenses.py) checks for remaining identified Ryzova-source AGPL markers; individual contributor/third-party rights still require review.
- **Commercial use:** GPLv3 permits commercial use under its terms; Ryzova does **not** offer a separate proprietary relicensing program. The inherited 9front tree and third-party assets retain their own licenses. See [commercial-use clarification](COMMERCIAL-LICENSING.md), [contributor licensing](docs/CONTRIBUTOR-LICENSING.md), and the [file-by-file GPLv3 migration audit](docs/GPLV3-MIGRATION-AUDIT.md).

Review the actual file headers and provenance before redistribution. See [license review](docs/LICENSE-REVIEW.md), [contributing](CONTRIBUTING.md), [trademarks](TRADEMARKS.md), and [security policy](SECURITY.md). This summary is not legal clearance for a binary distribution.

## Release gates and next work

An **official public Ryzova Kernel binary has not been authorized or published**. The [release candidate manifest](ryzova/release/amd64-preview-candidate.json) explicitly keeps `published: false` and approval fields unset. The [release notes](docs/RELEASE-NOTES-DRAFT.md) are a draft, **not** a release announcement.

Key remaining work includes completing finite named-application acceptance, broader adversarial/security and long-duration tests, physical AMD64 qualification, operational ARM64 build/boot/I/O evidence, documented driver/device coverage, independent reproducibility, complete artifact-scoped redistribution review, and explicit maintainer release approval.

**Experimental progress is real; general cross-platform compatibility and production readiness are not yet established.** Contributions and independently reproducible test reports are welcome under the project's [contribution rules](CONTRIBUTING.md).
