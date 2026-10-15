# Phase 4.0 — Ryzova Kernel stable development foundation

**Status:** Experimental AMD64 QEMU baseline only. Not a production-stable ABI, device certification, signed release, or permission to redistribute a complete kernel image. See [Phase 3 evidence](PHASE3.md), [legal release blocker #3](https://github.com/RyzovaTech/Ryzova-Kernal/issues/3), and [physical-hardware qualification #11](https://github.com/RyzovaTech/Ryzova-Kernal/issues/11).

## Known-good baseline

Phase 4.0 protects the last known-good Ryzova AMD64 development baseline before independent hardware-driver work.

- Pinned known-good commit: d6b1f3d8e78470f5ae9caf42d85deb983239e752.
- Historical recovery branch: baseline/amd64-phase4-0 (must never be rewritten). The full **commit SHA** is authoritative even if this ref is moved.
- Last independently passing native AMD64 QEMU run: [38708829586](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/38708829586), source commit ad60322c64b7cf15eaac3cb9d59037683d263b41.
- The diff from that tested commit to pinned baseline affects docs and the retired 9front sync file, **not kernel source**.
- Four pinned Git tree IDs cover sys/src/9, sys/include, amd64/include, and ryzova, in [baseline manifest](../ryzova/baselines/amd64-phase4.0.json).
- This phase changes **no hardware driver, kernel memory manager, scheduler, or kernel source**.

## CI and regression behavior

The [Phase 4 baseline workflow](../.github/workflows/phase4-baseline.yml) runs on PRs against main, pushes to main, and Phase 4 branches. It validates source tree hashes, ancestor relationships, absence of automatic 9front sync, and unit tests. It also drills a disposable local-only recovery branch and uploads JSON evidence.

The [native source-built QEMU boot workflow](../.github/workflows/phase3-native-build.yml) retains native mk, QEMU, 9P, storage, VirtIO and identity regression. Source, architecture headers, Ryzova metadata and build-test script changes trigger this workflow.

Run locally with a full Git history checkout:

    python3 scripts/phase4-baseline.py verify
    python3 -m unittest discover -s tests -p test_phase4_baseline.py -v

The baseline report under artifacts/phase4/ identifies kernel/build-input changes since the known-good commit. Its requires_new_native_qemu_test boolean **does not assert a build has passed**. A new physical driver requires model-specific testing; QEMU alone is not hardware qualification.

**GitHub branch protection is a separate administrator setting.** For full enforcement, protect main and the frozen baseline branch in Settings > Rules / Branch protection, require PR reviews and required CI status checks. The source/CI additions cannot prove that repository-level protection is enabled.

## Safe rollback — no force push

When a proposed kernel or driver update fails:

1. If not merged, stop the merge and read native QEMU/CI logs.
2. Verify the pinned source, commit provenance, and archived test evidence.
3. Preview recovery without modifying anything: python3 scripts/phase4-baseline.py prepare-rollback --name recovery/incident-001
4. Explicitly create **only a new local recovery branch**: python3 scripts/phase4-baseline.py prepare-rollback --name recovery/incident-001 --create-local-branch
5. Reproduce the source baseline kernel compile and QEMU boot and verify hashes. A Git commit by itself is **not** a deployable kernel image.
6. For already-merged bugs, revert or narrowly fix the offending change through a reviewed pull request. Never reset/force-push main or overwrite the frozen branch. Re-check against newer security fixes before reverting.
7. Verify the repaired kernel's QEMU evidence; physical hardware rollback requires separate recovery-media, snapshots and hardware testing.

The local rollback command does not change main, update a remote, touch drivers or install boot media. It refuses to overwrite an existing recovery ref.

## Phase 4.0 completion / exclusions

- [x] Known-good source baseline selected, four kernel-critical subtrees pinned.
- [x] Historical recovery branch created.
- [x] Automated integrity, source provenance and no-sync validation added.
- [x] Rollback dry run and local branch drill included in CI.
- [x] Existing native AMD64 source-built QEMU workflow preserved for driver/source changes.
- [ ] GitHub administrator must confirm required checks + baseline branch protection (repository setting).
- [ ] Physical hardware, boot-media rollback, signed releases and third-party legal clearance (future work).

**Phase 4.0 code and CI foundation is complete only once the branch and main checks succeed.** It does not certify physical devices, release stability or GitHub administrator settings.
