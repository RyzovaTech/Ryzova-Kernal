# 9front upstream integration (Phase 1)

## Authoritative references

- Original development site: https://git.9front.org/plan9front/plan9front/HEAD/info.html
- GitHub mirror used for fetching: https://github.com/9front/9front.git
- Mirrored branch: `front`
- Ryzova mirror branch: `upstream/front`

The GitHub repository is a mirror, so Ryzova's schedule cannot guarantee immediate propagation of changes made to the canonical repository.

## Provenance and synchronization

The scheduled workflow fetches the **full commit history** of upstream `front` and updates `upstream/front` using a non-forced fast-forward push.

- **No force pushes.** If upstream changes history, require human review before reconciling.
- **Never push upstream directly into `main`.** Fetching new driver code is not validation or approval of that code.
- **Do not run untrusted upstream build scripts with write credentials in the sync job.**
- **Keep upstream history, copyrights, and notices intact.** Perform a file-by-file license audit before adopting any imported code under a Ryzova release.
- **Check CI before integration.** The first integration must use a dedicated branch with a documented upstream SHA, compiler/toolchain requirements, and QEMU boot results.
- **No automatic deployment.** Updates can be reviewed, tested, then incorporated in a separate integration change.

## First integration (planned, not yet completed)

1. Confirm the `upstream/front` branch exists and resolves to the source commit being evaluated.
2. Create a separate integration branch from Ryzova development history.
3. Merge the unrelated source history only after review (using a local Git checkout with `--allow-unrelated-histories` if required).
4. Build baseline AMD64 9front with a documented, reproducible toolchain.
5. Test a 9front baseline boot in QEMU and capture logs and build artifacts.
6. After compliance review, merge approved integration through a protected pull request.

**Phase boundary:** Changes to the kernel identity, interfaces, or behavior belong in Phase 3. AGPLv3/commercial licensing proposals are **not** applied to inherited upstream files automatically.

## Failure policy

If fetching fails, credentials lack repository write permission, or the upstream history diverges: fail the workflow and leave existing refs unchanged. Review the GitHub Actions run and do not bypass the guard with a force push.
