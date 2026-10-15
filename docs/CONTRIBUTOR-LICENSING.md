# Contributor and outbound licensing rules — Phase 2

## Licenses attach to files and rights, not to the project name

| Origin / file class | Default outbound handling | Commercial relicensing |
| --- | --- | --- |
| Original Plan 9 / 9front | Original MIT terms where applicable plus listed exceptions | Ryzova cannot replace third-party grants or disclaimers |
| Special third-party dependencies / restricted fonts | Keep individual license and copying restrictions | Not covered by Ryzova commercial offers |
| New Ryzova-authored file explicitly marked `AGPL-3.0-only` | AGPLv3; license text in `LICENSES/` | Alternative agreement only if sufficient rights are held |
| New external AGPL contribution | AGPLv3 according to actual inbound grant | **Not** commercially relicensable by default |
| Externally sourced code under another license | Follow its exact text and compatibility obligations | Requires separately documented authorization |

## Contribution acceptance process

- Require a source/provenance statement for material code, generated assets, or substantial copied code.
- Check file- and directory-level notices before approving an import.
- New Ryzova-specific source should include `SPDX-License-Identifier: AGPL-3.0-only` **only** if its actual rights permit this.
- An AGPLv3 submission is **not** a copyright assignment.
- If the code is intended for a commercial alternative, obtain a **specific written contributor grant or agreement approved by counsel**. A DCO or a normal pull request alone does not establish proprietary relicensing rights.
- Where such a grant is unavailable, retain it only in an AGPL-compatible module or decline it for the dual-licensed component; never quietly claim rights.
- Maintain contributor credit, original copyright notices, license inventory and merge commit provenance.

## Open-source and commercial uses

Personal use, education, open-source projects and businesses may all use appropriately licensed code according to its license. AGPL imposes copyleft/source-sharing obligations in applicable circumstances; it is **not a “noncommercial only” license**. A separately signed commercial agreement is an alternative for covered rights-controlled files and may allow terms AGPL does not.

## Decisions needing human/legal sign-off

- Ownership and trademarks for Ryzova brand assets.
- Actual Contributor License Agreement form, if a dual-license grant is required.
- Commercial contract, warranty/indemnity scope, pricing and tax matters.
- File-level redistribution approval for upstream exceptions; no full clearance claimed.
