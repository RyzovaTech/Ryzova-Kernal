<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.0–6.5 Closeout — Experimental Source Only

The Phase 6 project now includes:

| Stage | Evidence | NOT claimed |
|---|---|---|
| **6.0** | deny-by-default allowlisted HMAC-authenticated messages, replay and quota tests | production key rotation or encrypted HMAC-alone transport |
| **6.1** | read-only 9P2000 binary wire messages, file-backed-by-memory service | native Ryzova Kernel network mount |
| **6.2** | pinned SHA256 checked 4 KiB public-data LRU pages | physical RAM or transparent swap |
| **6.3** | bounded pure integer-vector tasks, verified by independent computation | remote CPU cores or acceleration |
| **6.4** | guarded opt-in failure containment, bounded event telemetry, recovery tests | kernel crash recovery and real distributed reliability |
| **6.5** | localhost real TCP + TLS 1.3 mutual certificate authentication, pinned identities, real 9P cache and compute requests, outages and false peer rejection | authenticated external remote machines, native Ryzova-QEMU service execution |

**Verification:** full host suites across Python 3.11/3.12; Phase 6 closeout fail-closed metadata assertions; existing Phase 4/5 license/safety regression CI. The existing **native Ryzova AMD64 mk/QEMU boot workflow must pass for the PR head** before merging. That native QEMU job is independent and does not contain Phase 6 networking code. The Python services are NOT installed in a Plan 9 kernel process.

**Source integration, not feature certification:** the user requested Phase 6.4 and 6.5 complete and merge after CI. This authorizes merging only the experimental research sources to the repository, with zero automatic publication of kernel binaries. More work is required for real network peer deployment, secure persistent identities, revocation, observability on physical hardware, native process-level 9P mounting, safe cache integration and scheduler-backed delegated jobs. Kernel memory or CPU are **not** expanded by this branch. The retired 9front automatic sync stays disabled. Independent driver-agent work is left untouched.

Before announcing remote resources as a shipping product, require an actual remote-peer and native guest verification exercise, adversarial security review, rollback tests, hardware qualification, legal clearance, and public release maintainer approval.
