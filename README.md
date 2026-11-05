# Ryzova Kernel

**A New Life for a Forgotten Vision**

Ryzova Kernel is an **experimental, 9front-derived operating-system kernel project**. We are modernizing and extending the Plan 9/9front foundation, including its namespaces, 9P resource model, and network-oriented design, while exploring modern hardware, application compatibility and distributed resource services.

This project **builds upon Plan 9 and 9front**. It is not a from-scratch kernel, an official 9front release, or a production-ready operating system.

> **Current public status:** A source-built AMD64 development kernel has booted and passed functional smoke tests in QEMU. Research prototypes and limited integrations exist beyond that baseline, but broad application compatibility, real-hardware qualification, a security guarantee, and public redistributable binary releases have **not** been established.

**Start here:** [Try the source and checks](docs/COMMUNITY-QUICKSTART.md) · [Capabilities and limitations](docs/PROJECT-STATUS.md) · [Build details](docs/BUILD.md) · [Contribute](CONTRIBUTING.md) · [License map](LICENSE.md)

## What is here today?

- **Native kernel evidence:** The AMD64 kernel has been compiled with the 9front/Plan 9 toolchain, booted in QEMU, and checked for basic namespaces, process and memory behavior, kernel identity, 9P-backed ramfs I/O, and virtual networking. See [native QEMU build workflow](.github/workflows/phase3-native-build.yml) and [Phase 3.5 release gates](docs/PHASE3-5-RELEASE-GATES.md). A CI passing label is not a hardware certification.
- **Compatibility research:** Limited Linux ELF interpretation and scoped Windows PE / macOS Mach-O work exist; they do **not** establish general Linux, Windows or macOS application compatibility. See [Phase 5 closeout](docs/PHASE5-9-CLOSEOUT.md), [Phase 9 native subset](docs/PHASE9-2-COMPACT-NATIVE.md), and [project status](docs/PROJECT-STATUS.md).
- **Remote-resource research:** 9P and TLS-based experimental services and bounded coordination mechanisms are under development. Host-side prototypes are not a production distributed kernel or shared-memory multi-computer system. See [Phase 8.2 research](docs/PHASE8-2-MULTINODE-EXECUTION.md).
- **Driver work:** Source safety, controller-family tests, and legacy AMD64 preservation have active engineering. Hardware-model count, physical compatibility and long-running stability must be demonstrated, not inferred from IDs or tests.
- **Architecture:** AMD64 QEMU has verified kernel-boot evidence. ARM64 and additional cross-platform work remains subject to separate native-runtime and hardware qualification.

Some Linux, Windows, macOS, ARM64, and driver changes are **still in draft pull requests**. A draft PR is not automatically a feature shipped on `main`. Track the [open pull requests](https://github.com/RyzovaTech/Ryzova-Kernal/pulls) and the [status and limitations](docs/PROJECT-STATUS.md).

## Try it

This is a source project, not a downloadable end-user OS image.

On a machine with Git, Bash and Python 3:

```sh
git clone https://github.com/RyzovaTech/Ryzova-Kernal.git
cd Ryzova-Kernal
bash scripts/verify-foundation.sh
python3 -m unittest discover -s tests -p 'test_compact_contract_v1.py' -v
```

The first check validates provenance and required source files; the second exercises a research contract parser. **Neither boots the kernel.** To inspect the *actual* source-built AMD64 QEMU proof and the requirements for reproducing it, use the [community quickstart](docs/COMMUNITY-QUICKSTART.md) and [native-build CI workflow](.github/workflows/phase3-native-build.yml). Do not use this kernel for critical workloads.

## Direction and contribution

Our goal is to give the useful ideas of Plan 9 a new life through incremental, independently testable engineering. We welcome precise bug reports, documentation improvements, architecture discussion, reproducible QEMU results, hardware evidence, security review and carefully scoped drivers.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), the [issue tracker](https://github.com/RyzovaTech/Ryzova-Kernal/issues), and [SECURITY.md](SECURITY.md) for vulnerabilities. Keep performance and compatibility claims tied to concrete test evidence.

## Licensing and upstream provenance

**The repository is multi-licensed at the file/asset level.** Most inherited 9front code retains its original MIT licensing, with important third-party and file-level exceptions described in [`lib/legal/NOTICE`](lib/legal/NOTICE). Some Ryzova-authored files on `main` currently use **AGPL-3.0-only** markers. The project has selected **GPLv3 with optional commercial alternatives for eligible Ryzova-controlled code** as a future direction, but the [file-level migration and rights audit](docs/LICENSING-TRANSITION.md) are **not yet complete**; do not treat existing AGPL-marked files as already relicensed. Both GPLv3 and AGPLv3 permit commercial use under their respective conditions; an optional negotiated alternative covers only code for which the grantor controls sufficient rights.

See [LICENSE.md](LICENSE.md), [COMMERCIAL-LICENSING.md](COMMERCIAL-LICENSING.md) (current policy text pending migration), and [contributor licensing](docs/CONTRIBUTOR-LICENSING.md). There is no blanket relicensing of 9front or other third-party works.

The source retains original 9front Git ancestry and attribution. Historical `upstream/front` is kept for provenance; **automatic 9front synchronization is disabled**. Upstream resources: [9front](https://9front.org/) and [9front source](https://git.9front.org/).

**Release note:** No public kernel binary release has passed the separate distribution-rights and maintainer-authorization gates. See [release prerequisites](docs/PHASE3-5-RELEASE-GATES.md) and [release issue](https://github.com/RyzovaTech/Ryzova-Kernal/issues/9).
