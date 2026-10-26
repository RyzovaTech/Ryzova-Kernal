<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Main protection: administrator action still required

At the 2026-10-26 check, the repository is public, `main.protected` is false
and the repository ruleset list is empty. The connected GitHub App cannot
read/write branch-protection administration endpoints (403 integration access).
Passing CI and these instructions do not constitute enforced protection.

A repository administrator should create an active branch ruleset targeting
`refs/heads/main` that requires pull requests and successful current-branch
checks, blocks force pushes/deletion and has no routine bypass. Review
requirements should match the actual maintainer team; do not demand an
unavailable second reviewer in a solo repository and then silently bypass it.

Select the actual check-run contexts shown by a successful current PR,
including native-build and relevant TLS/9P/security checks. A workflow with a
path filter is not an unconditional required check; making it required for
every PR without an always-reporting workflow can deadlock documentation-only
PRs. Use always-reporting gate jobs if a universal aggregate is needed.

After saving, re-read the branch/ruleset state and inspect an unmerged test PR
with a deliberately failing required check. Confirm merge is blocked without
using a bypass, then close that test PR. Do not test enforcement by sending
a direct write/force push to main or publishing a binary.
