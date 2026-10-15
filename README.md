# Ryzova Kernel

**A New Life for a Forgotten Vision**

Ryzova Kernel is a proposed **9front-derived, general-purpose operating-system kernel foundation**. The goal is to retain the strengths of Plan 9/9front—namespaces, 9P, and network-oriented resource interfaces—while progressively developing Ryzova-specific kernel capabilities. The future RyzovaOS desktop and third-party OS variants are separate consumers of this kernel.

> **Project status:** Phase 1 — upstream source tracking. Ryzova Kernel is **not yet a boot-verified, independently developed kernel**.

## Source and branch policy

- **`main`**: Ryzova project control files, documentation, integration work, and future reviewed development.
- **`upstream/front`**: exact 9front `front` branch history, fetched and published by automation. **Do not commit Ryzova changes to this branch.**
- **Integration branches / pull requests**: proposed imports into Ryzova development after licensing review, compilation and regression tests.

Upstream source: [9front GitHub mirror](https://github.com/9front/9front), branch `front`. The canonical 9front project is at [9front.org](https://9front.org/), with source hosted at [git.9front.org](https://git.9front.org/).

The upstream branch is fetched automatically when the sync workflow runs. **Fetching upstream is not automatic deployment, merging, or a guarantee of build/driver compatibility.** A failed update must not overwrite the Ryzova development branch.

## Roadmap

1. **Phase 1:** repository bootstrap, full-history 9front upstream tracking, scheduled fetches, source verification and baseline build/boot planning.
2. **Phase 2:** copyright/license audit, contributor conditions, Ryzova marks and build conventions.
3. **Phase 3:** Ryzova kernel identity, changes to the 9front-derived kernel, AMD64 build and QEMU boot verification.
4. **Future phases:** native interfaces, carefully scoped compatibility subsystems, and optional external-resource services.

## License and attribution

No project-wide AGPLv3 or commercial relicensing of the imported 9front code is claimed at this stage. All upstream notices and third-party license obligations must be preserved. The proposed dual-license approach for **Ryzova-owned contributions** will be evaluated and documented in Phase 2; open-source AGPLv3 licenses do not prohibit commercial use.

See [Upstream integration policy](docs/UPSTREAM.md) for the sync design.
