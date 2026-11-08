# Ryzova GPLv3 migration — review ledger (Mission 1)

**Status:** IN PROGRESS. This is a review ledger, not a legal certification, a complete repository-wide SPDX inventory, or a grant of rights to third-party code.

## Decision and scope

- Ryzova's chosen outbound policy for **new and appropriately rights-controlled Ryzova-origin** files is `GPL-3.0-only`.
- The optional proprietary/commercial relicensing program is discontinued. GPLv3 continues to permit commercial use under its actual conditions.
- The inherited 9front/Plan 9 tree, notices and git history are **not relicensed or replaced**. Third-party exceptions remain file-specific.
- Previously distributed AGPLv3 copies retain valid existing grants. The full `LICENSES/AGPL-3.0-only.txt` text remains in the repository.
- This policy does not by itself convert existing `AGPL-3.0-only` file headers; specific files require checks and a deliberate tracked commit.

## Initial confirmed AGPL-marked candidates

These headers were read from `main` during the 2026-11-08 preliminary audit. **The list is illustrative, not exhaustive.** They are *migration candidates*, not automatically cleared for relicensing.

| File | Current observed SPDX | Review requirement |
| --- | --- | --- |
| `sys/src/9/port/devryzova.c` | `AGPL-3.0-only` | Confirm full rights in Ryzova-original implementation and contributions |
| `sys/src/9/port/ryzovadrvprobe.c` | `AGPL-3.0-only` | Check history and Ryzova-specific kernel adapter |
| `sys/src/9/port/ryzovadrvmatch.c` | `AGPL-3.0-only` | Check history and dependencies |
| `sys/src/9/port/ryzovadrvmatch.h` | `AGPL-3.0-only` | Check history and dependencies |
| `sys/src/9/port/ryzovapcirules.h` | `AGPL-3.0-only` | Generated file: verify generator inputs and source rights |
| `sys/src/9/port/virtgpuwire.c` | `AGPL-3.0-only` | Check wire-format provenance and history |
| `ryzova/compat/windows/loader.c` | `AGPL-3.0-only` | Check file history and any external contributions |
| `ryzova/compat/windows/api.c` | `AGPL-3.0-only` | Check file history and dependencies |
| `ryzova/compat/windows/cpu.c` | `AGPL-3.0-only` | Check interpreter-origin history |
| `ryzova/compat/windows/crt.c` | `AGPL-3.0-only` | Check source rights |
| `ryzova/compat/windows/files.c` | `AGPL-3.0-only` | Check source rights |
| `ryzova/compat/windows/pe64.c` | `AGPL-3.0-only` | Check source rights |
| `ryzova/compat/windows/native_runner.c` | `AGPL-3.0-only` | Check source rights |
| `ryzova/compat/windows/runtime.h` | `AGPL-3.0-only` | Check source rights |
| `ryzova/compat/windows/sync_objects.c` | `AGPL-3.0-only` | Check source rights |

Already observed with `GPL-3.0-only` headers: `ryzova/compat/linux/cpu.c`, `ryzova/compat/macos/macho64.c`, `ryzova/remote/trust.py` and `scripts/audit_licenses.py`. These samples do not establish all files' status or authorship.

## Per-file migration checklist

1. **Inventory:** enumerate all tracked project files, including generated headers, scripts, docs, and tests; use `python3 scripts/audit_licenses.py` and inspect its `explicit_spdx_files`. An SPDX header is only one piece of evidence.
2. **Ownership:** examine git history and every author or contributor, check copied/generated code and embedded third-party terms; seek written permission when Ryzova does not independently hold all required rights.
3. **Compatibility:** verify the target source and its dependencies may be distributed as proposed. Retain inherited copyright and license notices.
4. **Header update:** only after applicable rights checks, update the specific file's SPDX identifier to `GPL-3.0-only`, keep attribution, and record the paths/commit in the PR.
5. **Evidence:** check license inventory output, source builds and relevant tests; a green CI run does not certify legal rights.
6. **Release gate:** separately review the complete artifact and third-party fonts/programs before publishing an ISO, binary, or archive advertised as cleared.

## Review gates before declaring Mission 1 complete

- [ ] Complete tracked-file SPDX and ownership inventory (not just the examples above).
- [ ] Obtain necessary human confirmation for AGPL-to-GPLv3 changes; note any files with missing rights.
- [ ] Complete the authorized file-by-file migration; list unresolved AGPL material explicitly.
- [ ] Verify documentation and automated checks no longer advertise a separate proprietary relicensing program.
- [ ] Check all upstream notices and exceptions remain intact.
- [ ] Run relevant CI and review PR; merge only when the rights holder approves.

**Release caution:** This audit does not authorize a public Ryzova Kernel binary, branded ISO or complete source redistribution. See [LICENSE-REVIEW.md](LICENSE-REVIEW.md) and [RELEASE-NOTES-DRAFT.md](RELEASE-NOTES-DRAFT.md).
