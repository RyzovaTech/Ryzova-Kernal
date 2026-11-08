# Contributor and outbound licensing rules

## Repository licenses remain file-specific

Ryzova Kernel uses inherited 9front/Plan 9 code and a number of separately authored Ryzova and third-party components. **Do not describe the entire source tree as GPLv3-only.**

| Origin / file class | Outbound handling |
| --- | --- |
| Original Plan 9 / 9front | Keep the original MIT notices and every applicable exception |
| Third-party code, fonts, and assets | Preserve the applicable original rights, notices and restrictions |
| Newly authored Ryzova-owned source explicitly marked `GPL-3.0-only` | GPLv3-only, using `LICENSES/GPL-3.0-only.txt` |
| Existing Ryzova-origin `AGPL-3.0-only` source | Retain its existing license until an authorized file-specific GPLv3 migration is recorded |
| Historical AGPL-licensed copies | Earlier valid AGPLv3 grants remain in effect |
| Outside contributions | Rights as actually granted by their contributors; ordinary GPLv3 contributions remain GPLv3 |

## Open-source-only Ryzova policy

Ryzova is **not operating an optional proprietary/commercial relicensing program** for the project. Commercial use is permitted under GPLv3's actual terms; compliant businesses do not need to buy a separate Ryzova license. This is not a promise that every upstream or third-party asset is under GPLv3 or can be included in a distributable image.

## Contribution acceptance

- Record source provenance, contributor/copyright ownership, upstream derivation, third-party dependencies, and any generated or assisted code.
- Preserve original copyright statements, file-level notices, and upstream history.
- New original Ryzova source should carry `SPDX-License-Identifier: GPL-3.0-only` **only when the necessary copyright holders authorize that license**.
- A pull request or Developer Certificate of Origin does **not** assign copyright to Ryzova; no contributor assignment is presumed or required for ordinary GPLv3 contributions.
- Do not silently convert AGPL-only, mixed-rights, or unmarked files to GPLv3. For each candidate, record its author/history, external contributions and exact changes, then obtain any missing permissions before updating the header.
- Review combined-code license compatibility and the contents of any distribution artifact separately. CI license inventory is not legal certification.

## Migration notes

Previously published Ryzova-origin AGPL copies remain available under their earlier terms. A new, properly authorized GPLv3 offer applies to the specific version/file published under GPLv3; it does not revoke grants to older copies.

Maintain the review checklist in [GPLv3 migration audit](GPLV3-MIGRATION-AUDIT.md), consult [LICENSE.md](../LICENSE.md), and retain the historical AGPL license text. The 9front upstream contribution policy is distinct and must be followed for contributions submitted upstream.

## Human sign-off still required

Confirm rights for individually migrated files, any additional contributors or copied material, compatibility with third-party obligations, redistribution of entire source or binary artifacts, and trademark representations. This document is not a legal opinion or a completed clearance.

See [LICENSE.md](../LICENSE.md), [GPLv3 commercial-use clarification](../COMMERCIAL-LICENSING.md) and [LICENSE-REVIEW.md](LICENSE-REVIEW.md).
