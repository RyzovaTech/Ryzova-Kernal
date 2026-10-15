# Preliminary upstream license review — Phase 2 update

**Not a final legal audit and not a project-wide relicensing.**

The imported 9front tree carries `lib/legal/NOTICE` and `lib/legal/mit`. Its NOTICE states that original Plan 9 and, by default, 9front changes are MIT-licensed unless otherwise indicated. Preserve these files in all source distributions.

The NOTICE explicitly lists important exceptions:

- Certain Lucida screen/printer fonts in `lib/font/bit/lucida` and `sys/lib/postscript/font` are subject to restrictions against redistributing independently of Plan 9 and against derivative works.
- Printer fonts in `sys/lib/ghostscript/font` have GNU GPL version 2 notices.
- The Ghostscript program under `sys/src/cmd/gs` has an Aladdin Free Public License notice.
- Source/Terminus bitmapped fonts under `lib/font/bit/` have SIL Open Font License notices.
- Other files may carry individual COPYING, COPYRIGHT or LICENSE terms.

**Action before binary/source distribution:** review each of the above paths (including any missing, moved, or additional files), collect file-level license inventory, classify redistributability, and exclude/relicense incompatible payloads when necessary. Do not imply that all repository contents may be copied as MIT or AGPLv3.

**Phase 2 policy files now present:** see `LICENSE.md`, `COMMERCIAL-LICENSING.md`, `TRADEMARKS.md`, `docs/CONTRIBUTOR-LICENSING.md` and the CI-generated inventory. The audit is an automated inventory, **not comprehensive legal clearance**. AGPLv3 does not forbid compliant commercial usage. Ryzova cannot grant proprietary rights to code it does not own or have sufficient relicensing permission for.

Source references: `lib/legal/NOTICE`, `lib/legal/mit`, `lib/legal/contributing` in the imported upstream history.
