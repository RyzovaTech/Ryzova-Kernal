# Ryzova Kernel — licensing

Ryzova Kernel is an experimental **9front/Plan 9-derived** source project. Its repository contains **MIT-licensed upstream code, GPL-3.0-only Ryzova-origin code, and separately licensed third-party material**. **There is no single blanket license for every file.** Check the file's own notices and provenance before reuse or distribution.

## Quick reference: MIT + GPLv3

| Component | Applicable license |
| --- | --- |
| Original Plan 9 and 9front source | **MIT**, unless a file or upstream notice states a different license or restriction |
| Ryzova-origin code lawfully marked `SPDX-License-Identifier: GPL-3.0-only` | **GNU General Public License, version 3 only** |
| Bundled third-party programs, drivers, fonts, data and other assets | **Their original notices, licenses and restrictions** |
| Previously published Ryzova versions under AGPL-3.0-only | **Existing AGPLv3 grants remain valid**; later GPLv3 offers do not revoke them |

**MIT covers the inherited upstream foundation; GPLv3 covers eligible Ryzova-origin additions.** A GPLv3 header on a Ryzova file does not convert an unrelated 9front or third-party file to GPLv3.

## 1. Upstream 9front / Plan 9 — MIT and exceptions

Retain upstream copyright statements, Git history and file-level notices. The authoritative upstream notices in this tree include:

- [`lib/legal/NOTICE`](lib/legal/NOTICE) — upstream license summary and exceptions
- [`lib/legal/mit`](lib/legal/mit) — upstream MIT license text
- Individual `LICENSE`, `COPYING`, `COPYRIGHT` and other file-level notices

**Not everything inherited from 9front is ordinary MIT code.** The upstream notice identifies separate restrictions for Lucida fonts, GPL-2.0 printer fonts, Ghostscript under the Aladdin Free Public License, and fonts under the SIL Open Font License, among other file-level exceptions. In particular, some assets may **not** be freely redistributed separately. Do not remove their notices or assume they are covered by Ryzova's GPLv3 policy.

## 2. Ryzova-origin additions — GPL-3.0-only

Ryzova-origin source that the relevant copyright holders are authorized to license and that is explicitly marked `SPDX-License-Identifier: GPL-3.0-only` is offered under the [GNU GPL version 3 only](LICENSES/GPL-3.0-only.txt).

GPLv3 is a free and open-source license: commercial use is permitted when its conditions are followed. When distributing GPL-covered work, comply with applicable notices, license-copy and corresponding-source obligations. **Ryzova does not operate a separate proprietary code-relicensing program.**

A project's origin label or Git commit author does not by itself prove all copyright and relicensing rights. Contributors and maintainers must review copied material, generated content and outside contributions where relevant.

## 3. Historical AGPLv3 code

Some earlier Ryzova-origin code was offered under `AGPL-3.0-only`. Properly granted rights to those **previously distributed versions remain valid**. Later, authorized GPLv3 relicensing does not withdraw earlier AGPLv3 grants.

We retain [`LICENSES/AGPL-3.0-only.txt`](LICENSES/AGPL-3.0-only.txt) for historical grants and any material that may still use those terms. Source is relicensed file-by-file only where rights permit; no repository-level statement overrides a file that remains subject to other terms.

The [GPLv3 migration audit](docs/GPLV3-MIGRATION-AUDIT.md) documents the source-header migration and its limitations; it is not independent copyright-chain certification.

## 4. Combining, modifying and redistributing

- **Read the actual notices** for each source file and dependency. Keep original copyright and attribution statements intact.
- MIT-licensed source can generally be incorporated into GPLv3-covered combined works if the relevant conditions are respected; that does **not** erase upstream MIT grants or notices.
- Other third-party licenses may require separate analysis or may prevent a particular combined distribution.
- Source availability and passing CI are **not** legal clearance or security certification for boot images, ISOs, or packaged binaries.
- Use the [contributor licensing rules](docs/CONTRIBUTOR-LICENSING.md) for incoming code; see [commercial-use clarification](COMMERCIAL-LICENSING.md) for the no-proprietary-relicensing policy.

## 5. Project references

- [`docs/LICENSE-REVIEW.md`](docs/LICENSE-REVIEW.md) — known exceptions and outstanding release review
- [`lib/legal/NOTICE`](lib/legal/NOTICE) — inherited upstream notices
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute with provenance and tests
- [`TRADEMARKS.md`](TRADEMARKS.md) — names and marks are separate from source code permissions

**Summary:** **9front/Plan 9 upstream: MIT subject to exceptions. Ryzova-origin authorized additions: GPL-3.0-only. Other material: its own license.** This map describes current source policy; it is **not** a legal opinion or redistribution certification.
