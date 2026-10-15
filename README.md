# Ryzova Kernel

**A New Life for a Forgotten Vision**

Ryzova Kernel is a **9front-derived general-purpose kernel project**. The plan is to retain and extend the strengths of Plan 9/9front—namespaces, 9P and network-oriented resource interfaces—while developing Ryzova-specific capabilities. RyzovaOS and third-party OS variants are future consumers of this kernel.

> **Status: Phase 1 source integration completed; native AMD64 build and QEMU boot not yet verified.** The imported tree is the upstream 9front kernel/system, not yet a separately working Ryzova kernel.

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
- Native build and QEMU boot procedure: [docs/BUILD.md](docs/BUILD.md) (**not yet performed**).
- Preliminary licensing findings: [docs/LICENSE-REVIEW.md](docs/LICENSE-REVIEW.md).

## Roadmap

1. **Phase 1:** clone, history-preserving merge and safe upstream tracking. Source integrity checks done; native boot verification pending.
2. **Phase 2:** file-level license audit, contributor conditions, Ryzova marks and build conventions.
3. **Phase 3:** Ryzova kernel identity, AMD64 build/boot verification and Ryzova kernel interfaces.
4. **Later:** native APIs, scoped binary compatibility, optional external resources and community SDK.

## License and attribution

The imported 9front code retains its upstream notices, including `lib/legal/NOTICE` and its listed exceptions. **This repository is not globally relicensed AGPLv3**, nor is third-party code offered under a Ryzova proprietary license. A potential AGPLv3/commercial dual-license model for **Ryzova-owned additions** is subject to Phase 2 rights review. AGPLv3 does not prohibit compliant commercial use.

See [upstream integration policy](docs/UPSTREAM.md).
