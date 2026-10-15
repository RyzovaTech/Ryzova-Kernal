# Ryzova Kernel

[![Ryzova-owned code: AGPLv3](https://img.shields.io/badge/Ryzova--owned%20code-AGPLv3-blue)](LICENSES/AGPL-3.0-only.txt) [![9front: MIT + exceptions](https://img.shields.io/badge/9front-MIT%20%2B%20exceptions-orange)](lib/legal/NOTICE) [![Commercial alternative: Ryzova rights only](https://img.shields.io/badge/commercial%20alternative-Ryzova%20rights%20only-lightgrey)](COMMERCIAL-LICENSING.md)

**A New Life for a Forgotten Vision**

Ryzova Kernel is a **9front-derived general-purpose kernel project**. The plan is to retain and extend the strengths of Plan 9/9front—namespaces, 9P and network-oriented resource interfaces—while developing Ryzova-specific capabilities. RyzovaOS and third-party OS variants are future consumers of this kernel.

> **Status: Phase 3 native AMD64 development build is verified in QEMU, including a Ryzova-specific read-only identity device and basic userspace/namespace smoke tests.** Experimental only; no stable ABI, real-hardware compatibility certification, or cleared public binary release.

## Branches and source

- **`main`**: 9front full source tree and original Git ancestry, plus Ryzova documentation, CI and reviewed integrations.
- **`upstream/front`**: exact upstream `9front/9front` branch history, fetched and updated by automation. Never commit Ryzova changes there.
- **`integration/*`**: reviewed changes and future upstream merges prior to integrating into `main`.

Upstream: [9front GitHub mirror](https://github.com/9front/9front) (`front` branch). Original project: [9front.org](https://9front.org/); source: [git.9front.org](https://git.9front.org/).

Initial integrated upstream revision: `a0806493926c04ce90d4e4a46961dec30a1054dd`, imported through [Pull Request #1](https://github.com/RyzovaTech/Ryzova-Kernal/pull/1) with full original history.

**Upstream sync fetches commits only; it does not auto-merge to `main`, deploy changes, or prove a new driver works.** Build and review gates are required before future integrations.

## Verification and build

- Source-history, layout and license-notice checks: [GitHub Actions](https://github.com/RyzovaTech/Ryzova-Kernal/actions).
- AMD64 kernel source: `sys/src/9/pc64/`.
- Native AMD64 build, freshly built kernel boot, identity, and denied-write checks: [successful CI run](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38703531423) and [docs/BUILD.md](docs/BUILD.md).
- Ryzova identity: `cat '#Z/version'` → `Ryzova Kernel 0.1.0-dev`, plus [native device API documentation](docs/kernel-api/RYZOVA-DEVICE.md).
- Source-built QEMU kernel runs native `rc` and passed read-only `#Z`, `/proc`, `/net`, process namespace bind, a real 9P `ramfs` read/write, 9fat boot-filesystem access and VirtIO HTTP GET tests. Physical hardware, exhaustive regression and legal clearance remain pending.
- Experimental [AMD64 build profile](ryzova/config/amd64.default.json), [version metadata](ryzova/metadata/kernel-version.json) and [Phase 3 evidence report](docs/PHASE3.md).
- Pre-Phase 3 boot checks and the difference between an upstream release VM and a kernel built from this repository: [docs/PRE-PHASE3-BOOT.md](docs/PRE-PHASE3-BOOT.md).
- Preliminary licensing findings: [docs/LICENSE-REVIEW.md](docs/LICENSE-REVIEW.md).
- Phase 3.5 verified QEMU test and independent Guest/Host SHA-256 equality: [CI run #38708363099](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38708363099); [preview release gates](docs/PHASE3-5-RELEASE-GATES.md). **No public kernel binary release authorized.**


## License, community and project policy (Phase 2)

**This repository is multi-licensed at the file/asset level.** Most inherited 9front code is MIT-licensed as described in `lib/legal/NOTICE`, with significant exceptions; it is **not** globally relicensed AGPLv3. Newly authored Ryzova files expressly marked `AGPL-3.0-only` use the bundled AGPLv3 text. A commercial alternative may be offered for specific code when rights are fully controlled, but **AGPL allows commercial use**.

- [License map](LICENSE.md) · [AGPL text](LICENSES/AGPL-3.0-only.txt) · [License review](docs/LICENSE-REVIEW.md)
- [Commercial licensing scope](COMMERCIAL-LICENSING.md) · [Contributor rights](docs/CONTRIBUTOR-LICENSING.md)
- [Contribution guide](CONTRIBUTING.md) · [Trademark and naming policy](TRADEMARKS.md)
- [Build standards](docs/BUILD-STANDARDS.md) · [Branding](docs/BRANDING.md)
- [Phase 2 report](docs/PHASE2-REPORT.md) · [license inventory CI](.github/workflows/license-audit.yml)

The generated inventory is **not** a complete clearance for third-party redistribution or a substitute for legal counsel. Do not claim an official Ryzova kernel binary release until verified build/boot tests and release/legal requirements pass.

## Roadmap

1. **Phase 1:** clone, history-preserving merge and safe upstream tracking completed. Native source build and boot verification were subsequently completed in Phase 3.0.
2. **Phase 2:** repository-wide rights map and source licensing inventory, contributor and commercial policies, marks, build conventions and license CI. Human legal approval for third-party redistribution and contracts is still required.
3. **Phase 3:** native AMD64 build + fresh boot verified; Ryzova read-only `#Z` version interface and profile/CI checks implemented. Real hardware and cleared developer preview remain pending.
4. **Later:** native APIs, scoped binary compatibility, optional external resources and community SDK.

## License and attribution

The imported 9front code retains its upstream notices, including `lib/legal/NOTICE` and its listed exceptions. **This repository is not globally relicensed AGPLv3**, nor is third-party code offered under a Ryzova proprietary license. The policy for **Ryzova-owned additions** is AGPL-3.0-only where expressly marked, with optional, separately negotiated commercial alternatives only when sufficient rights exist; no commercial license contract has yet been executed. AGPLv3 does not prohibit compliant commercial use.

See [upstream integration policy](docs/UPSTREAM.md).
