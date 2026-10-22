<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 8 — Advanced Kernel & Remote Resource Engineering (research entry)

## Entry condition and Phase 7 closeout record

PR #47 integrated the guest-native TLS 1.2 pinned SHA-256 certificate research
path. PR #48 adds bounded ingress concurrency, a 9P frame quota, defensive
listener cleanup, and negative recovery tests. **PR #48 was merged into main
only after all 20 exact PR-head GitHub Actions workflows passed**, including
a fresh AMD64 source build, actual QEMU boot, native TLS/9P mount/read/guest
SHA-256, kernel-provenance assertions and Phase 4–7 regressions.

These were CI experiments using QEMU slirp and loopback test endpoints. The
native guest authenticates a pinned **server** certificate using its existing
tlsclient functionality (TLS 1.2); it does not present a qualified mutually
authenticated client identity. The separate gateway-to-peer connection uses
pinned mutual TLS 1.3. These are **two different TLS sessions**. Neither
production guest-to-peer end-to-end mTLS nor real physical remote nodes were
verified. Physical RAM expansion, additional CPU cores, release certification
and production security are NOT claimed. Issues #39 and #31 remain open.

## Phase 8.0: security architecture foundation (this source change)

New host-only Python research module: ryzova/remote/phase8_trust.py.
Tests: tests/test_phase8_trust.py.
CI: .github/workflows/phase8-trust-policy.yml (Python 3.11/3.12).

The immutable research policy starts **disabled**, and rejects reads unless
a policy has been explicitly enabled. It enforces a bounded peer-identity
allowlist, the pinned SHA-256 digest of a caller-supplied authenticated TLS
leaf certificate (DER), an exact flat-file read allowlist, maximum 4096-byte
requested read count, explicit policy expiration, and explicit monotonic
generation updates for offline peer revocation and fingerprint rotation.
Only a read-authorization operation is modeled. Denials avoid storing or
returning certificate bytes, private material, file names, or exception
details. Malformed, overlong, duplicated, stale, revoked, path-traversal and
unauthorized inputs are denied in the standalone regression tests.

**Critical integration boundary:** a plain tls_authenticated=True argument
is not a trusted cryptographic assertion. Only a TLS transport that has
independently verified the remote certificate, hostname/peer identity,
protocol and peer-leaf DER may call this policy. The module does not parse
X.509, authenticate an external caller, verify a TLS handshake or establish
a server channel; it is **not wired into live native Ryzova QEMU/9P**.
The expires_at attribute is the policy validity bound, not proof of X.509
certificate validity. The offline pin update API is not PKI revocation,
secure provisioning, persistence, or an administration authorization
protocol. Before real integration, a trusted identity-to-certificate
binding and a secure privileged policy-update path are mandatory.

## Phase 8 staged implementation gates

- **8.0:** stand-alone fail-closed host trust-policy prototype and tests;
  actual native TLS/9P integration **not yet complete**.
- **8.1:** authenticated native 9P service integration, namespace lifecycle,
  controlled mount/unmount, native read permission and disconnect handling.
- **8.2:** isolated VM and separate-machine TLS peer tests including network
  partition, certificate mismatch, restart and fault injection.
- **8.3:** integrity-checked, bounded remote data cache with local fallback
  (not physical RAM enlargement).
- **8.4:** explicit sandboxed delegated pure computations and verification
  (not extra local CPU cores).
- **8.5:** actual hardware and driver qualification in coordination with
  the independent driver agent.
- **8.6:** fuzzing, long-run reliability, credential lifecycle and independent
  security assessments.
- **8.7:** reproducible artifact and license review plus separate maintainer
  release decision. No automatic publication.

All Phase 8 source merges require exact-head CI verification, preserving
native QEMU and existing driver regression gates. The host-only policy must
not be represented as new native kernel functionality.

Do not touch hardware-driver agent files, re-enable automated 9front sync,
claim Linux/Windows/macOS application compatibility, or close release
blockers without evidence. Keep issue #36 open for native Linux app execution.
