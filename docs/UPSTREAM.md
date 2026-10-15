# 9front upstream integration (Phase 1)

## Authoritative references

- Original development site: https://git.9front.org/plan9front/plan9front/HEAD/info.html
- GitHub mirror used for fetching: https://github.com/9front/9front.git
- Mirrored branch: `front`
- Ryzova mirror branch: `upstream/front`

The GitHub repository is a mirror, so sync timing follows that mirror rather than guaranteeing immediate propagation from the canonical development repository.

## Provenance and synchronization

The scheduled workflow fetches the **full Git history** of the upstream `front` branch and updates `upstream/front` via a non-forced fast-forward push.

- **No force pushes.** An upstream history rewrite requires maintainer review.
- **Never automatically merge upstream into `main`.** New driver code requires testing and approval.
- **Do not run upstream build scripts using a token with repository write privileges.**
- **Retain original ancestry and legal notices**, including all license exceptions.
- **Release and future update integrations require compiler/test review,** not only source-layout validation.

## First source integration — completed

- Initial upstream source revision: `a0806493926c04ce90d4e4a46961dec30a1054dd`.
- History preserved by a two-parent integration commit on `integration/9front-baseline`, retaining original Ryzova and upstream ancestors.
- Integrated via [Pull Request #1](https://github.com/RyzovaTech/Ryzova-Kernal/pull/1).
- Phase 1 source-provenance and license-notice structural CI checks passed on the integration branch.
- Original `upstream/front` remains separately synced.

**Still pending:** native amd64 compilation, QEMU boot logs, runtime regression tests, comprehensive file-level rights audit. See [BUILD.md](BUILD.md) and [LICENSE-REVIEW.md](LICENSE-REVIEW.md). Source import is not a release or proof of kernel usability.

## Future upstream updates

1. Compare `main` with `upstream/front` and record target SHA.
2. File/license review for changed and new content.
3. Create a dedicated integration branch; do not overwrite `main` or force-update histories.
4. Build with a known, checksum-pinned 9front toolchain/image; capture logs.
5. Run QEMU boot and regression tests, then obtain maintainer review.
6. Merge approved changes into `main` through a pull request.

**Phase boundary:** Kernel identity/ABI/behavior changes begin in Phase 3. Phase 2 will specify rights of Ryzova-owned contributions; upstream files are not automatically AGPLv3 or commercially relicensed.

## Failure policy

If fetching fails, permissions fail or histories diverge, fail the sync job. Leave branch refs untouched. Review logs rather than bypassing safety checks.
