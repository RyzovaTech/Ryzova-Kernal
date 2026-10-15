# Phase 2 completion report — policy and automation

**Scope:** contributor and outward-facing rights rules, brand/marks conventions, build standards and automated inventory. This is **not** a legal opinion, complete copyright clearance, native build or a boot certification.

## Deliverables

- [x] Repository-level license map: `LICENSE.md`.
- [x] Canonical AGPLv3-only legal text for future, **expressly marked** Ryzova-authored files.
- [x] Commercial alternatives policy clarifying that AGPLv3 permits commercial use.
- [x] Contributor guide and detailed relicensing-rights policy.
- [x] Project brand naming / marks / attribution guidelines.
- [x] Ryzova native toolchain, source layout and release criteria.
- [x] Automation to enumerate tracked legal notices and SPDX headers in a downloadable inventory.
- [x] CI checks for retained 9front legal notices and new policy infrastructure.

## Known exceptions noted in `lib/legal/NOTICE`

| Affected tree | Upstream indication | Action |
| --- | --- | --- |
| `lib/font/bit/lucida`, `sys/lib/postscript/font` | Restricted Lucida fonts | Verify redistribution as a whole, independent derivative restrictions |
| `sys/lib/ghostscript/font` | GPL v2 printer fonts | Verify font-specific notices and package distribution |
| `sys/src/cmd/gs` | Aladdin Free Public License program | Obtain legal compatibility/redistribution review |
| `lib/font/bit/source`, `lib/font/bit/terminus` | SIL OFL fonts | Verify specific files and attribution |
| Additional `COPYING`, `COPYRIGHT`, `LICENSE` markers | Other source-level exceptions | Classify individually from generated inventory |

## Verification limits and outstanding human decisions

- The inventory is a **candidate list**, not authoritative license detection or permission to redistribute the contents.
- Any unresolved restricted third-party component must be assessed or excluded **before shipping public redistributed binaries or repackaged assets**.
- Human rights-holder verification and legal counsel are needed for actual commercial license and CLA execution.
- Native AMD64 build/QEMU boot and runtime driver validation remain future technical milestones.
- No third-party component has been made AGPL-only or sublicensed commercially by these documents.

The technical Phase 2 policy/automation setup is complete when the Phase 2 PR CI succeeds. The separate formal legal sign-off remains unresolved and cannot be manufactured by a CI workflow.
