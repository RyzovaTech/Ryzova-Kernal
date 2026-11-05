# Ryzova Kernel — license map

**Ryzova Kernel is an open-source, multi-licensed source tree. There is no single license grant for the entire repository.** Always follow the applicable license and copyright notices for each file.

## Ryzova-owned original code

Newly authored source files for which Ryzova holds **all necessary relicensing rights** and which are expressly marked:

```
SPDX-License-Identifier: GPL-3.0-only
```

are offered under the **GNU General Public License version 3 only (GPLv3)**. A verbatim copy is at [`LICENSES/GPL-3.0-only.txt`](LICENSES/GPL-3.0-only.txt).

**GPLv3 permits commercial use** in compliance with its terms. Ordinary GPL-compliant commercial use does **not** require a separate paid license.

This change supersedes the project's *future Ryzova-owned licensing policy*, not copyright rights held by someone else. Any original Ryzova files previously offered under `AGPL-3.0-only` retain that earlier valid grant for recipients of those versions. The historical full AGPLv3 text remains at [`LICENSES/AGPL-3.0-only.txt`](LICENSES/AGPL-3.0-only.txt). A historical copy marked AGPLv3 is still governed by the original grant; a new explicitly GPLv3-marked version is offered under its stated terms. This does not automatically relicense third-party contributions.

## Original Plan 9 / 9front source

The inherited 9front source tree retains its complete Git history and copyright/license notices. Original Plan 9 and 9front work is generally MIT-licensed **unless otherwise indicated**. Read [`lib/legal/NOTICE`](lib/legal/NOTICE), [`lib/legal/mit`](lib/legal/mit), and any file-level `LICENSE`, `COPYING`, `COPYRIGHT` and other legal notices.

Important exceptions include restricted fonts and independently licensed software. No GPLv3 badge, Ryzova policy document, or paid Ryzova license can overwrite original third-party rights. Files in a Ryzova-named directory are not automatically Ryzova-owned; imported material retains its original terms.

## Optional, separately negotiated commercial licensing

Where Ryzova holds sufficient rights in **specified Ryzova-controlled additions**, Ryzova may separately offer a paid commercial agreement with alternative terms. This is **optional**, not a condition for normal GPLv3-compliant commercial use. No commercial offer is automatically granted by this notice.

Commercial alternatives cannot silently include 9front or other independently owned third-party material, patents, trademarks or outside contributions. See [`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md).

## Contributors and downstream recipients

Contributors retain their copyright unless explicitly agreed otherwise; a pull request, DCO, or GPLv3 contribution does **not** automatically give Ryzova proprietary relicensing rights. Additional written permission is necessary for an optional commercial alternative that covers a contributor's work. See [`docs/CONTRIBUTOR-LICENSING.md`](docs/CONTRIBUTOR-LICENSING.md).

This map is not a legal review or certification of every redistributed artifact. Before binary releases, review upstream exceptions and third-party distribution obligations in [`docs/LICENSE-REVIEW.md`](docs/LICENSE-REVIEW.md). Ryzova marks are handled separately in [`TRADEMARKS.md`](TRADEMARKS.md).
