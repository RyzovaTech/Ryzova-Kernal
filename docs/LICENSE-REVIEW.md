# Preliminary upstream license review — Phase 2 update

**Not a final legal audit and not a project-wide relicensing.**

The imported 9front tree carries `lib/legal/NOTICE` and `lib/legal/mit`. Its NOTICE states that original Plan 9 and, by default, 9front changes are MIT-licensed unless otherwise indicated. Preserve these files in all source distributions.

The NOTICE explicitly lists important exceptions:

- Certain Lucida screen/printer fonts in `lib/font/bit/lucida` and `sys/lib/postscript/font` are subject to restrictions against redistributing independently of Plan 9 and against derivative works.
- Printer fonts in `sys/lib/ghostscript/font` have GNU GPL version 2 notices.
- The Ghostscript program under `sys/src/cmd/gs` has an Aladdin Free Public License notice.
- Source/Terminus bitmapped fonts under `lib/font/bit/` have SIL Open Font License notices.
- Other files may carry individual COPYING, COPYRIGHT or LICENSE terms.

**Action before binary/source distribution:** review each of the above paths (including any missing, moved, or additional files), collect file-level license inventory, classify redistributability, and exclude/relicense incompatible payloads when necessary. Do not imply that all repository contents may be copied as MIT, GPLv3 or AGPLv3.

**Current policy:** see `LICENSE.md`, `COMMERCIAL-LICENSING.md` (GPLv3/commercial-use clarification; **no separate proprietary relicensing program**), `TRADEMARKS.md`, `docs/CONTRIBUTOR-LICENSING.md`, `docs/GPLV3-MIGRATION-AUDIT.md` and the CI-generated inventory. The inventory is **not comprehensive legal clearance**. GPLv3 and historical AGPLv3 permit compliant commercial use under their respective terms. Eligible Ryzova-controlled code can receive a new GPL-3.0-only grant only after file-level ownership checks; earlier AGPL grants remain valid. No third-party or upstream rights are changed by this policy.

Source references: `lib/legal/NOTICE`, `lib/legal/mit`, `lib/legal/contributing` in the imported upstream history.
