# Priority 0 — GitHub Actions queue and runner recovery (2026-11-03)

These are observed counts, not proof of a billing failure or GitHub outage.
Ryzova-Kernal is public. On 2026-11-03 the Actions REST API reported
847 queued workflows, 21 in progress and 1,734 workflows created that UTC day.
Linux PR #81 had 34 queued workflows at its former exact head.

## Changes

Four Linux-only workflows now use workflow-name-plus-PR-number concurrency
to cancel superseded PR revisions while preserving separate branch workflows.
Manual workflow_dispatch invocations have unique run IDs and are not cancelled.
The musl target-build workflow already had PR-scoped concurrency and is unchanged.
CLX-04 ISA discovery now uses Linux path filters rather than running for
unrelated Windows/macOS-only changes.

These changes cannot retrospectively clear existing queues, add runner slots,
or resolve account billing problems. Native AMD64 QEMU CI is shared with
other platform agents and is deliberately not modified from this Linux PR.
No disabled checks, weakened acceptance, frozen-version swaps, or merge bypass.

## Operator-side diagnostic steps

1. GitHub Actions: filter queued and in_progress and inspect the exact
   waiting reason, job label, selected runner, and elapsed wait.
2. Settings > Actions > General: check policy, enablement and permissions.
3. Account Billing / Actions usage and budgets: check actual billed usage,
   spending caps and runner entitlements. Standard hosted public-repo runs
   differ from paid larger runner usage; do not assume billing root cause.
4. Cancel only obsolete PR runs via Actions UI, not latest-head required jobs.
5. If new latest-head jobs still cannot start, collect run/job IDs and queue
   durations and request GitHub Support review of scheduling/account limits.
6. Revalidate exact-head native AMD64/QEMU, musl source targets, ISA and
   security workflows. Queued status and older commit success are not proof.

References:
https://docs.github.com/en/actions/reference/limits
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency
https://www.githubstatus.com/
