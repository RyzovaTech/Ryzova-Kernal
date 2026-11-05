# Contributor rights and outbound licensing

The Ryzova public policy is **GPL-3.0-only for source legitimately offered by the applicable Ryzova rights holder**, and an **optional separately negotiated commercial alternative** for specific code with sufficient relicensing rights. No blanket license replaces inherited third-party notices.

| Origin / file class | Public handling | Optional commercial alternative |
| --- | --- | --- |
| Original Plan 9 / 9front | Retain applicable MIT and file-level exceptions | Ryzova cannot override these third-party rights |
| Third-party libraries, fonts and assets | Retain all actual source notices and restrictions | Not covered unless independently authorized |
| Ryzova-owned source actually tagged `GPL-3.0-only` | GPLv3-only; full text in `LICENSES/GPL-3.0-only.txt` | May be separately licensed only with sufficient grantor rights |
| Historical or still-tagged `AGPL-3.0-only` source | Applicable AGPLv3 terms remain in force for existing versions and files | No automatic alternative without adequate rights |
| External GPLv3 contributions | GPLv3 as granted by actual rights holders | **No automatic proprietary relicensing permission** |
| External code under another license | Its own actual terms, including compatibility requirements | Needs documented alternative authorization |

## Required process for contributions

1. Identify author, original source, licenses, copied snippets and any third-party code.
2. Preserve upstream history and copyright notices; new Ryzova-origin files should have a correct SPDX header.
3. Do not assume that a DCO, PR, issue contribution or GPLv3 submission assigns copyright to Ryzova.
4. If optional proprietary licensing is intended for a contributor's code, obtain a **specific written grant/CLA accepted by the contributor and reviewed appropriately** before that code is dual-licensed. If absent, treat the contribution only under its actual inbound license.
5. Check build-system and dependency license compatibility; **GPLv2-only, AGPLv3, AFPL, MIT and font exceptions are not interchangeable**.
6. Keep contributor credits and review actual files before downstream distribution.

GPLv3 allows compliant commercial use. A separate commercial agreement is an *option*, never a condition for exercising existing GPLv3 rights. Historical recipients of AGPLv3 versions retain their rights. For actual redistribution/commercial agreements, perform an independent legal review.

See [LICENSE.md](../LICENSE.md), [COMMERCIAL-LICENSING.md](../COMMERCIAL-LICENSING.md), [docs/LICENSE-REVIEW.md](LICENSE-REVIEW.md) and [TRADEMARKS.md](../TRADEMARKS.md).
