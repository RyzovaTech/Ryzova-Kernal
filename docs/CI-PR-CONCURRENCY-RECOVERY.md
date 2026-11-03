# Priority 0: repo-wide Actions queue storm hardening

Repository snapshots on November 3, 2026 showed 1,022 queued workflows,
16 running and more than 10,000 historical runs, including many
near-simultaneous Windows/macOS/Linux branch revisions.
This evidence indicates trigger overload; it is NOT proof of a GitHub
platform outage, disabled runners or an account billing problem.

All 56 original pull-request workflows now share one safe policy,
including the formerly globally cancelling Phase 4 baseline workflow:

    concurrency:
      group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
      cancel-in-progress: ${{ github.event_name == 'pull_request' }}

For pull-request events only, old revisions in the SAME WORKFLOW and SAME PR
are superseded. Main/release branch pushes and manual dispatch runs use unique
run IDs and are never cancelled by the policy. Existing CI jobs, checks,
triggers and security/release requirements remain unchanged. A policy
validation script, unit tests, and CI guard prevent accidental regression.

Limits: these source changes do not cancel historical queued runs or
increase account runner capacity. Repo Actions/billing control is outside
the connected app's available operations. An authorized account operator
may cancel only obsolete runs, review Actions budget and runner allocation,
and escalate to GitHub Support with queued job IDs as necessary.

Operational completion REQUIRES real new-head Linux target-build, AMD64/QEMU,
ISA, networking/security and other required workflows completing.
This CI-only change MUST NOT be interpreted as passing Linux V1 acceptance
or authorizing a merge of the incomplete feature PR #81.

GitHub concurrency docs:
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency
