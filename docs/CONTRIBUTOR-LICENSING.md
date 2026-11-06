# Contributor and outbound licensing rules

## Project-level licensing is a map, not a blanket assignment

| Origin / file class | Public outbound handling | Alternative commercial license |
| --- | --- | --- |
| Original Plan 9 / 9front | Retain original MIT terms plus all exceptions | No independent Ryzova relicensing rights in upstream code |
| Special third-party code, programs, fonts | Preserve the exact original rights and restrictions | Not covered without authorization |
| Verified Ryzova-controlled source marked `GPL-3.0-only` | GPLv3 only; text in `LICENSES/GPL-3.0-only.txt` | Possible only when every necessary right is held |
| Previously licensed AGPL-3.0-only Ryzova code/copies | Earlier AGPL grants remain valid; only appropriately authorized files are also now offered GPLv3 | Requires sufficient rights, not implied by earlier AGPL license |
| New external GPLv3 contribution | GPLv3 under the actual submitted grant | **Not** commercially relicensable by default |
| Other outside contribution | Applicable source license plus compatibility review | Requires written authorization |

## Contribution acceptance

- Record source provenance, copyright holder, external dependencies and any copied or assisted code.
- Verify original copyright notices before accepting material from Plan 9/9front or elsewhere.
- Use `SPDX-License-Identifier: GPL-3.0-only` for a newly authored Ryzova component **only if** the contributor has the rights to grant that license. Do not overwrite third-party headers.
- A normal pull request, GPLv3 grant or Developer Certificate of Origin **does not assign copyright to Ryzova**. An optional proprietary/commercial arrangement requires an additional legally adequate written rights grant or agreement for every relevant contribution.
- Keep contributors' credit, original notices and history. Do not silently convert legacy AGPL-only or mixed-rights files.
- Continue recording exact-commit licensing evidence. Licensing inventory automation is not a full copyright-chain audit.

## Open source and commercial uses

GPLv3 permits personal, educational, research and commercial use under its terms. **Commercial use is not prohibited and a Ryzova commercial license is optional, not mandatory.** GPLv3 distribution obligations differ from historical AGPLv3 network-use obligations. Previous AGPL license grants are not cancelled.

## Human/legal sign-off still required

Confirm rights in contributions and reused material; precise commercial agreement language and contributor permissions; independent upstream redistribution restrictions; trademark ownership; any warranty, indemnity and compliance promises.

See [LICENSE.md](../LICENSE.md), [COMMERCIAL-LICENSING.md](../COMMERCIAL-LICENSING.md) and [docs/LICENSE-REVIEW.md](LICENSE-REVIEW.md).
