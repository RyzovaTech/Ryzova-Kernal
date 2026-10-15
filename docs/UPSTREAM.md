# 9front source provenance — automated sync retired

**Current policy (2026-10-15):** Ryzova Kernel no longer automatically fetches, imports, or merges 9front source updates. The former `.github/workflows/sync-9front.yml` was deleted from `main`. This is a historical-origin record, **not** an active update plan.

## Original source attribution

- Original 9front project: https://9front.org/
- Original source: https://git.9front.org/plan9front/plan9front/HEAD/info.html
- GitHub mirror previously used for the initial import: https://github.com/9front/9front
- Initial imported upstream revision: `a0806493926c04ce90d4e4a46961dec30a1054dd`
- Ryzova historical branch: `upstream/front` (**retained, not synchronized**)

Original upstream Git ancestry was preserved by a history-preserving merge, through [Pull Request #1](https://github.com/RyzovaTech/Ryzova-Kernal/pull/1). Keeping this origin record and the original `lib/legal` notices does **not** mean that Ryzova receives or publishes any future upstream updates.

## What was removed

The deleted GitHub Actions workflow previously had:
- A daily schedule (`23 2 * * *`, UTC).
- A manual `workflow_dispatch` action to invoke the same upstream sync.
- A `push` trigger tied to changes in the sync workflow itself.
- A write-capable step fetching 9front's `front` history and advancing Ryzova's `upstream/front` branch.

**None of those update mechanisms remain in `main`.** The existing historical `upstream/front` branch has not been deleted or rewritten. No code, drivers or kernel configurations were changed when disabling synchronization.

## Ryzova's independent development

Ryzova Kernel development continues on `main` with normal code review and existing build/boot testing. Future driver updates are Ryzova-managed work, **not** automatic imports from 9front. The original 9front provenance and the applicable third-party licenses must still be preserved.

The Phase 3 QEMU native-build test may use a **pinned official 9front release disk as a toolchain bootstrap environment**. It does not fetch a moving source branch or automatically update Ryzova's kernel or drivers. A fixed toolchain dependency is distinct from upstream code synchronization.

## Verification

To verify the removal:
1. Confirm `.github/workflows/sync-9front.yml` is absent on `main`.
2. Inspect the remaining `.github/workflows/` definitions; no 9front source mirror schedule should be present.
3. Confirm `main` and the historical `upstream/front` ref are unchanged by any new automatic sync.
4. Existing source, license, and native build/boot checks must remain enabled.

The kernel is still **derived from** the imported 9front source, and that attribution is independent of the decision to discontinue syncing.

