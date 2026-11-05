# Contributor and outbound licensing rules

## Licenses attach to files and copyright holders

| Origin / file class | Default handling | Optional alternative commercial rights |
| --- | --- | --- |
| Original Plan 9 / 9front | Retain original MIT terms when applicable, plus file-level exceptions | Ryzova cannot replace upstream and third-party grants |
| Independently licensed fonts, libraries, firmware or assets | Retain original terms and notices | Not automatically covered |
| Original Ryzova-owned file expressly marked `GPL-3.0-only` | **GPLv3 only**, text in `LICENSES/GPL-3.0-only.txt` | Possible **only when** all required rights are held |
| Earlier Ryzova file/version marked `AGPL-3.0-only` | Historical AGPLv3 grants remain valid for those versions | Depends on rights; transition does not withdraw prior grants |
| New external GPLv3 contribution | GPLv3 under the submitted copyright holder's valid grant | **Not commercially relicensable by Ryzova by default** |
| Other licensed material | Follow actual inbound grant and compatibility obligations | Only with separately documented permission |

## New contribution policy

- Identify the source and copyright/provenance for material new code and generated assets. Never submit code you have no right to license.
- Preserve existing upstream copyright statements and special exceptions.
- For **new original Ryzova-controlled code**, use `SPDX-License-Identifier: GPL-3.0-only` where rights and compatibility allow.
- **Do not copy or change old AGPLv3 identifiers without copyright-holder authority.** Ryzova's GPLv3 policy covers eligible Ryzova-controlled work, not every file in a Ryzova-named directory.
- A pull request, DCO sign-off or GPLv3 license is **not** a copyright assignment or a grant of additional proprietary relicensing rights.
- If proposed code is intended to be included in a separately commercial-licensed component, obtain an explicit, sufficient **written contributor grant** reviewed by appropriate counsel **before** offering those alternative terms.
- If permission is not available, preserve the contribution under its authorized public license where compatible, keep it out of the optional commercial offer, or decline it.
- Record contributor credit, provenance, source commits, SPDX markers and test evidence.

## Public and commercial use

The GPLv3 and AGPLv3 are open-source licenses permitting compliant commercial use. Ryzova does **not** charge a mandatory license fee for business use of Ryzova-owned GPLv3-marked code under GPLv3. A separate paid alternative covers only negotiated and controlled rights.

## Human approval still required

- Rights inventory and ownership verification for any file-level relicensing;
- trademark rights and any separate branding permissions;
- contributor commercial relicensing grants, if desired;
- actual commercial contract, warranties, terms, taxes and pricing;
- third-party distribution clearance and software release authorization.

This policy does not override earlier grants or any third-party license. See [`../LICENSE.md`](../LICENSE.md), [`../COMMERCIAL-LICENSING.md`](../COMMERCIAL-LICENSING.md) and [`LICENSE-REVIEW.md`](LICENSE-REVIEW.md).
