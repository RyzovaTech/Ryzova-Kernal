# Ryzova Kernel — file-level license map

**Ryzova Kernel is a multi-license source tree, not a single blanket GPLv3 work.** Different files retain their own copyright holders and license conditions. Refer to each file, the inherited notice and this inventory before copying or redistributing.

## Plan 9 / 9front inherited code

Imported Plan 9 and 9front sources retain their original licenses, generally MIT unless otherwise stated. Review [`lib/legal/NOTICE`](lib/legal/NOTICE), [`lib/legal/mit`](lib/legal/mit) and each file-level LICENSE/COPYING/COPYRIGHT notice. The inherited tree includes restrictive fonts, GPLv2 material, Aladdin Free Public License material and other exceptions. **Ryzova does not assert ownership or blanket relicensing rights over that code.**

## Ryzova-origin code

Code **actually marked `SPDX-License-Identifier: GPL-3.0-only`** and offered by a rights holder with sufficient authority is licensed under [GNU General Public License version 3, only](LICENSES/GPL-3.0-only.txt). The SPDX marker describes the outbound license claim for that specific file, not for every source or asset in this tree.

Earlier versions of Ryzova-origin files were published with **`AGPL-3.0-only`** terms; the [full original AGPLv3 text](LICENSES/AGPL-3.0-only.txt) remains for historical recipients, other still-AGPL-marked files and license provenance. Publishing a new version under GPLv3 does **not** revoke existing recipients' valid AGPLv3 rights. Some files maintained by independent contributors or driver-development work may retain different identifiers until individually audited.

**Unmarked files and imported libraries are not automatically GPLv3.** Any third-party contributions require appropriate rights, copyright attribution and separate assessment before a proprietary alternative can be offered.

## Commercial usage and optional alternative agreements

**GPLv3 explicitly permits commercial use and commercial distribution under its conditions.** Neither companies nor other users must buy a license solely for commercial use. A separate negotiated **optional** proprietary/commercial license may be offered only for specified Ryzova-controlled files where all required alternative-licensing rights are held. It cannot replace inherited 9front grants, third-party license requirements or other copyright holders' rights. Read [COMMERCIAL-LICENSING.md](COMMERCIAL-LICENSING.md).

## Compliance and provenance

See [docs/LICENSE-REVIEW.md](docs/LICENSE-REVIEW.md), [docs/CONTRIBUTOR-LICENSING.md](docs/CONTRIBUTOR-LICENSING.md), [TRADEMARKS.md](TRADEMARKS.md), and the preliminary `scripts/audit_licenses.py` inventory. File-by-file clearance, contributor rights, compatibility and downstream redistribution must be checked before any actual packaged release; a passing automated inventory is **not legal certification**.
