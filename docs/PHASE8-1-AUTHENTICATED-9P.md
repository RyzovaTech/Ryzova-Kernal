<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 8.1 — Authenticated 9P Services (experimental host integration)

## Scope of this branch

Optional host-side TLS-transport-bound authorization is connected to the existing
isolated read-only 9P peer. No driver or kernel source code was changed.
The production system remains disabled and uncertified.

Source: `ryzova/remote/phase8_9p_service.py`, with opt-in hooks in
`ryzova/remote/native_bridge.py` and `ryzova/remote/phase7_fixture.py`.

End-to-end experimental data path:

1. Source-built Ryzova AMD64 guest in QEMU uses existing native `tlsclient`,
   verifies a pinned TLS 1.2 **server** leaf, and mounts/reads read-only 9P.
2. CI host TLS 1.2 ingress forwards 9P to localhost gateway (plaintext
   inside this **host only**, not a cryptographically end-to-end channel).
3. Host gateway connects to 9P peer via actual mutual TLS 1.3. The peer
   requires a client certificate, verifies a pinned certificate fingerprint,
   then, in the Phase 8.1 **opt-in test path**, extracts the TLS client's DER
   leaf directly from its live SSLSocket. The peer matches that DER to the
   configured immutable Phase 8.0 trust policy before and during processing.
4. For every TREAD, the guard uses this connection's native 9P FID map to
   resolve a **file name**, bounds the byte count, and checks current policy.
   Cross-session FID values do not grant access. Disallowed operations still
   fail closed. TLS EOF, policy revocation, timeout or malformed messages never
   trigger transparent retry, plaintext fallback, or request replay.

The mTLS identity being authenticated at step 3 is the **host gateway
client**, NOT the Ryzova guest. Mounts still use test-only `mount -n`;
there is no forwarded verified guest identity, no guest client certificate
and no claim of per-human-user ACL enforcement. The existing Phase 7
backward-compatible research fixture continues to operate without opt-in
Phase 8 policy; it must never be called a production access-control mode.

## Security checks and evidence

Tests `tests/test_phase8_native_9p_service.py` exercise real TLS 1.2
guest-facing ingress + TLS 1.3 mutually authenticated peer socket traffic
with SHA-256 content comparison, default-deny policy, wrong leaf fingerprint,
revoked/expired policy, wrong peer identity, unauthorized file scope,
mid-session revocation, malformed FID reads, concurrent independent FID
tables, prohibited writes, and explicit outage/reconnect behavior.

CI `.github/workflows/phase8-native-9p.yml` runs Python 3.11/3.12 socket
security tests plus Phase 7 protocol regressions. The existing native AMD64
source-build/QEMU workflow is mandatory for exact-head acceptance. Host
Python tests alone do **not** demonstrate the newly integrated policy running
inside the Ryzova guest. The Ryzova guest's prior native TLS/9P mount/file/SHA
path must remain green and unchanged.

## Remaining blockers and future subphases

- No authenticated **guest** 9P user/client identity or secure per-user
  namespace. This would require protocol-bound guest credentials and an
  authorization model independent of the host gateway.
- No trusted privileged management API, persistent key store or revocation
  distribution. The policy snapshot may be updated only by the trusted host
  test harness; local field mutation is not an administration protocol.
- No separate VM/external machine, production PKI, full threat audit,
  native QEMU fault-injection qualification, signed release or physical
  hardware certification. Phase 8.2 will address separate network nodes.
- No remote physical RAM expansion or additional local CPU cores.
- Keep GitHub Issues #39, #31 and #36 open.

Phase 8.1 requires exact-head CI success and a merge decision. Before an
authenticated native **guest** 9P service can be claimed, additional kernel
implementation and native QEMU cryptographic identity evidence are necessary.

Automatic 9front synchronization stays disabled. Driver-engineering agents'
files and CI must not be overwritten.
