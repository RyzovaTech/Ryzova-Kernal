# Ryzova Kernel — file-level license map

**This repository contains multiple inherited and Ryzova-origin licenses. No single license governs the entire inherited 9front / Plan 9 source tree.** Ryzova's current policy is GPL-3.0-only for newly authored source it is authorized to license, without a separate proprietary licensing program.

## Inherited 9front / Plan 9 sources

The 9front Git history and [`lib/legal/NOTICE`](lib/legal/NOTICE), [`lib/legal/mit`](lib/legal/mit) and file-level COPYING, COPYRIGHT and LICENSE notices remain unchanged. Inherited Plan 9 and 9front changes are generally available under MIT terms **unless otherwise indicated**. Some bundled fonts, programs and assets have different or restrictive licensing. Ryzova does not claim ownership of or the ability to commercially relicense these third-party materials.

## Ryzova-origin GPL-3.0-only source

Ryzova-controlled, newly authored source explicitly marked `SPDX-License-Identifier: GPL-3.0-only` is licensed under the [GNU General Public License version 3 only](LICENSES/GPL-3.0-only.txt). This is a **free and open-source license**, including for commercial use when its terms are followed. Redistribution, modifications and corresponding-source obligations follow the GPLv3 text.

This change is limited to files for which Ryzova has sufficient outbound licensing authority. Identifying a file as Ryzova-specific does **not** prove every contribution is owned by one holder. Review file history, outside contributions and reused material before treating any file as sufficiently rights-controlled for a new GPLv3 offer.

## Historical AGPL-3.0-only grants

Earlier Ryzova-origin files were published with `SPDX-License-Identifier: AGPL-3.0-only`. Recipients of previously issued AGPLv3 copies retain their license rights; the new offer does not revoke those grants. The [AGPLv3 text](LICENSES/AGPL-3.0-only.txt) is kept for history and for any remaining AGPL-marked material. A file not expressly and lawfully relicensed is **not** converted by this summary alone.

## No separate proprietary licensing program

Ryzova is **not offering a separately negotiated proprietary license** for project code as part of this open-source policy. GPLv3 permits compliant **commercial use**; companies do not need a fee-based Ryzova license to exercise GPLv3 rights. Inherited 9front/Plan 9 and other third-party material stays under its actual original license. See [commercial-use clarification](COMMERCIAL-LICENSING.md) and [contributor rules](docs/CONTRIBUTOR-LICENSING.md).

**Migration is file-by-file, not retroactive:** AGPL-marked source remains under its existing notices unless and until every needed rights holder authorizes a new GPLv3 grant and the relevant file is updated. Earlier valid AGPLv3 permissions remain available to recipients. See [GPLv3 migration audit](docs/GPLV3-MIGRATION-AUDIT.md).

## Compliance and distribution

Unmarked upstream or legacy files are **not** automatically GPLv3; inspect their actual copyright and license notices. Preserve complete upstream attribution, all exceptions and individual notices. Public binaries and images require separate redistribution clearance and release authorization, not just a top-level license statement.

See [docs/LICENSE-REVIEW.md](docs/LICENSE-REVIEW.md), [lib/legal/NOTICE](lib/legal/NOTICE) and [TRADEMARKS.md](TRADEMARKS.md).

*This is a source-level project license map, not a legal opinion or certification of redistribution rights.*
