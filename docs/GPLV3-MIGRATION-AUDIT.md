# Ryzova Kernel — GPLv3 source migration (Mission 1)

**Technical status (2026-11-08): migration implemented on the review branch.**
**Legal status: no independent copyright-chain or binary-redistribution certification.** This document is a source-level migration report, not a legal opinion.

## Decision

- Ryzova's outbound policy for appropriately rights-controlled **Ryzova-origin source** is `GPL-3.0-only`.
- The optional proprietary/commercial code-relicensing program is discontinued.
- GPLv3 permits commercial use under its terms; compliant GPLv3 users do not need to purchase another license.
- The inherited 9front/Plan 9 tree and third-party copyrights, licenses and notices are **not** relicensed.
- Already issued AGPLv3 versions keep their historical grants. `LICENSES/AGPL-3.0-only.txt` remains in the repository.

## File-level migration implementation

The changes in pull request #118 replace `SPDX-License-Identifier: AGPL-3.0-only` with `GPL-3.0-only` on **155 identified Ryzova-origin source, tests, build scripts, and tooling files**, without otherwise rewriting their implementations.

| Ryzova-origin area | Migrated headers |
| --- | ---: |
| `ryzova/` compatibility runtimes and build scripts | 47 |
| `scripts/` driver, reference and compatibility tooling | 43 |
| `sys/` Ryzova-added kernel/device/USB helpers | 14 |
| `tests/` Ryzova source fixtures and qualification tests | 51 |
| **Total** | **155** |

The `sys/` list includes explicitly added AMD64 kernel extensions, ARM64 `m5ecam`, USB `hciwire` and `m1class` files. This audit used tracked-file enumeration and a comparison against the pinned 9front upstream source commit `a0806493926c04ce90d4e4a46961dec30a1054dd` to identify Ryzova-added source paths. A new path in Git does **not** prove independent originality or ownership.

### Generated code and CI

- `scripts/m0_native_rules.py` now emits `GPL-3.0-only` in its generated `ryzovapcirules.h` header, so future generation is consistent with the migrated file.
- `scripts/check-identity.py` now expects `GPL-3.0-only` on the native `devryzova.c` device source.
- `scripts/audit_licenses.py` scans native source, Python, PowerShell (`.ps1`), Plan 9 rc (`.rc`) and Ryzova `mkfile` build scripts; it lists `ryzova_agpl_migration_candidates` and **fails** if identified Ryzova-source files still carry `AGPL-3.0-only` headers. This does not turn the inventory into legal title verification.
- The original `lib/legal/NOTICE`, `lib/legal/mit`, upstream history, third-party license texts and their exceptions are retained.
- Unmarked or inherited portions, including `ryzova/compat/windows/hjfs/` foundation files without Ryzova SPDX headers, are not blanket relicensed.
- The historical Phase 2 report has a superseded-policy note instead of being rewritten to misstate history.

## Reproducible checks

From a full repository checkout, run:

```sh
python3 scripts/audit_licenses.py
python3 scripts/check-identity.py
python3 scripts/m0_native_rules.py --check
bash scripts/verify-foundation.sh
```

Inspect `artifacts/license-inventory.json`, especially `ryzova_agpl_migration_candidates`, `errors`, explicit SPDX headers and `upstream_exceptions`. Review the latest CI runs and actual logs. A green inventory proves only its configured assertions.

## Rights and redistribution boundaries

1. The Ryzova source policy is intended for code over which the relevant copyright holders have sufficient rights. **Git authorship, repository ownership and an SPDX header alone do not prove this.**
2. For external contributions, copied/generated content or third-party portions, maintainers must verify all required grants before relying on a new GPLv3 offer.
3. Historical AGPLv3 rights granted to earlier recipients are not cancelled or made conditional on accepting GPLv3.
4. Combined images, boot media, fonts, Ghostscript and other assets require **separate artifact-level licensing and redistribution review**. This migration does not authorize a public binary or ISO.
5. The no-proprietary-license policy is a project decision; it does not undo pre-existing third-party contracts, if any.
6. Plan 9/9front code maintains its original copyright and license notices, including MIT and applicable exceptions; no claim of exclusive Ryzova ownership is made.

## Checklist

- [x] Identify new-source files relative to pinned upstream and inspect Ryzova-origin AGPL headers.
- [x] Update 155 identified Ryzova AGPL source/test/tooling headers to GPLv3-only in the review branch.
- [x] Keep original Plan 9/9front sources and notices unchanged.
- [x] Preserve historical AGPL license text and older grants.
- [x] Correct generator template, identity assertion, license inventory and contributor-policy text.
- [x] Retire separate proprietary/commercial code relicensing offer in policy documentation.
- [ ] Confirm every relevant author/contributor and any copied or generated material has sufficient GPLv3 relicensing rights; external independent legal review if required.
- [ ] Verify final CI results after all changes and record any exceptions.
- [ ] Complete independent artifact-by-artifact rights review before publishing a kernel binary/ISO.

**Source migration does not equal production or distribution release approval.** See [LICENSE-REVIEW.md](LICENSE-REVIEW.md), [LICENSE.md](../LICENSE.md) and [RELEASE-NOTES-DRAFT.md](RELEASE-NOTES-DRAFT.md).
