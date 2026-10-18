<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 4 closeout — AMD64 Ryzova Kernel and Phase 5 entry (experimental)

**Meaning of 'complete' here:** The planned Phase 4.0–4.9 engineering **infrastructure** is integrated in `main` and verified by unit tests, protected source baseline checks and source-built AMD64 QEMU runtime CI. This is **not** a declaration of production reliability, physical hardware certification or a binary release.

## Phase evidence
- **4.0:** pinned AMD64 baseline and non-destructive local recovery drill.
- **4.1:** bounded 512 KiB ramfs allocation, process lifecycle, scheduler progress and `#Z` read-only validation from fresh boot.
- **4.2:** independent D-series driver agent evidence and regression workflows (not proof of physical devices).
- **4.3:** 9front native `mk` developer build profile and pinned guest-image checksum (not independent compiler or bitwise reproducibility).
- **4.4:** `experimental-0` kernel identity/9P/namespace interface contract, **not stable ABI**.
- **4.5:** additional bounded 256 KiB ramfs and three-child QEMU checks, 6 positive checks and negative-case unit tests (not multi-hour soak).
- **4.6:** physical hardware test evidence schema and intentionally blocked release if unavailable.
- **4.7:** exact Git source trees and build input provenance, not cross-host binary reproducibility.
- **4.8:** minimal experimental community variant schema; no downstream OS binary tested.
- **4.9:** fail-closed release candidate authorization checker; no public binary published.

## Consolidated verification

Run:
```sh
python3 -m unittest discover -s tests -p 'test_phase4_closeout.py' -v
python3 scripts/phase4_closeout.py
```
Reports at `artifacts/phase4/final-closeout.json`. For live kernel verification, require the **separate Phase 3 native-build workflow** green for the **same exact commit**: native `mk`, fresh QEMU reboot, 9P/storage/network, Phase 4.1 and Phase 4.5 tests and kernel SHA integrity.

## Phase 5 entry — compatibility research, NOT shipped compatibility

Start a new Phase 5 **experimental** branch (do not modify the frozen baseline); begin with:
1. executable formats and Linux ELF ABI research, a supported initial AMD64 syscall subset, and a documented security boundary;
2. design the namespace-facing `/compat/linux` view as a runtime interface, **not** the assumption that folders alone execute Linux binaries;
3. implement loader/runtime prototypes with unit tests and negative tests, then verify under the native QEMU kernel before any claim that apps run;
4. reserve Windows and macOS ABI work for separate audited later gates;
5. preserve copyright/License attribution and do not revive automatic 9front source synchronization.

**Blockers unaffected:** physical hardware testing, true stress/fuzz/credential hardening, independent reproducibility, stable public ABI, rights-holder/legal signoff, maintainer release authorization and verified signing. See [Issue #31](https://github.com/RyzovaTech/Ryzova-Kernal/issues/31), [#3](https://github.com/RyzovaTech/Ryzova-Kernal/issues/3), [#9](https://github.com/RyzovaTech/Ryzova-Kernal/issues/9) and [#15](https://github.com/RyzovaTech/Ryzova-Kernal/issues/15).
