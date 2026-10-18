<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 7 — Verified entry baseline (research handoff)

**Entry status:** Ryzova's native AMD64 QEMU 9P bridge is a source-built and tested kernel feature in the following **limited experimental sense**:

Linux CI-host read-only 9P2000 server (bound to 127.0.0.1) -> QEMU user-mode TCP gateway 10.0.2.2 -> fresh source-built Ryzova AMD64 Plan 9-derived kernel -> `srv -nq` + `mount -n` -> `/n/ryzova6/probe` read -> guest `sha1sum -2 256` -> host SHA256 comparison. The file content contains the exact checkout Git commit. Native guest logs and TCP-frame counts independently demonstrate actual guest/server activity.

## Phase 7 entry quality gate

`scripts/phase7_handoff.py` runs **after** the existing real QEMU test and independent kernel extraction, not on fabricated fixture data. It requires all of:
- native 9P evidence JSON with 6 positive checks, matching exact checkout commit and SHA256, and >=5 actual 9P frames;
- full source-built kernel provenance: identical guest compiled, guest installed, and independently extracted Linux-host binary SHA256, all tied to the source commit;
- runner result with genuine native `mk` success, fresh userspace boot and Phase 6 mounted 9P digest success;
- kernel public binary distribution remains BLOCKED pending separate qualification.

Missing, inconsistent or mismatched evidence fails the workflow. Unit tests use synthetic records only to prove the gate rejects forgery; those tests **alone** are not native proof. The actual QEMU workflow runs independently and must pass.

## Potential Phase 7 engineering direction (proposal, not approved scope)

- **7.0:** secure native guest network transport design, identity provisioning and threat model;
- **7.1:** native authenticated read-only 9P client gateway or isolation proxy (mutual TLS), with downgraded/plaintext attempts rejected;
- **7.2:** separate remote-VM peers, disconnect/fault recovery and process credentials/namespace tests;
- **7.3:** content-hash-pinned remote data cache with isolation and bounded usage — **not equivalent to physical RAM**;
- **7.4:** delegated stateless remote compute and actual cross-machine performance measurements — **not extra local CPU cores**;
- **7.5:** fresh Ryzova QEMU guest ↔ separate remote guest end-to-end, negative security tests, long-running fault injection, rollback;
- **7.6:** qualify hardware evidence, rights/redistribution, maintainer signoff, release governance.

This is a **proposed Phase 7 plan**, not a commitment or claim the listed implementations exist. The user can choose a different Phase 7 goal. Existing driver-agent work must be preserved, and 9front automatic source sync stays off.

## Safety and release restrictions

The currently verified QEMU 9P mount is **plaintext and unauthenticated**, only safe for a disposable, public read-only fixture. No native client TLS, cross-physical-machine proof, remote RAM/page-fault integration, new local CPU cores, production credentials, or public release is established. Remote resources remain opt-in and non-release. Issue #39 records the outstanding native security and external-network qualification work; Issue #31 retains Phase 4 public-release blockers.

This handoff is **Phase 7 research-ready**, not production-ready.
