<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 7 guest-native TLS 9P: research security status

This document supersedes the **guest-to-gateway plaintext** description in
`PHASE7-5-6-QEMU-CLOSEOUT.md` for the separately merged native-TLS test path.
It does not alter that earlier research experiment or its provenance.

## Implemented, bounded experimental topology

Ryzova source-built AMD64 QEMU guest (native `tlsclient`, test-provisioned
SHA-256 leaf fingerprint, negotiated TLS 1.2) -> CI Linux loopback TLS
termination / read-only 9P ingress -> CI Linux loopback 9P gateway -> pinned
mutual TLS 1.3 -> loopback read-only 9P peer.

The guest-to-ingress TLS connection and gateway-to-peer TLS connection are
**two distinct TLS sessions**. The guest has **server-authentication only**:
there is no guest client certificate or end-to-end guest-to-peer mTLS.
`sys/src/cmd/tlsclient.c` supports `-t` thumbprint policy, `-x` exclusions,
`-n` server name, and optional `-c` certificate bytes; their presence is not
evidence of verified guest mTLS or deployable enterprise key management.

The experimental CI serial harness passes a short-lived leaf SHA-256 pin in
`/tmp/ryzova7-trusted`. The guest's actual negotiated protocol is checked
against a TLS 1.2-only host ingress. Do not infer TLS 1.3 guest support from
host Python/OpenSSL or from upstream mTLS.

## Fail-closed boundaries and residual Phase 7 tests

- Ingress binds only `127.0.0.1`. QEMU slirp exposes host loopback through
  `10.0.2.2`; this is not a secure general-purpose listening arrangement.
- Ingress accepts only the read-only 9P request-type allowlist, validates
  bounded frame sizes and matching upstream transaction tags, and returns
  a 9P Rerror for disallowed requests without forwarding them.
- Admission is capped **before creating handler threads** (default 8 active
  guest sessions, configurable from 1 to 32 in the test fixture). Excess
  connections are rejected; active slots are released on all handler exits.
- Each TLS ingress session is bounded to 256 attempted 9P frames by default
  (configurable from 1 to 4096 for controlled research tests). Exceeding this
  quota terminates the session without silent request replay.
- The timeout for a TLS handshake, socket I/O, and upstream connect is 6s.
  An EOF, bad frame, rejected TLS handshake, or upstream disconnect closes
  the session. Recovery requires an explicit **new** TLS and 9P session.
- Tests exercise TLS version mismatch, untrusted certificate, plaintext
  handshake rejection, malformed frame length, denied writes/unsupported
  operations, client admission exhaustion, frame quota, upstream failure
  and explicit recovery, and concurrent independent FID namespaces.
- The Phase 3 workflow still compiles and boots a fresh Ryzova AMD64 kernel,
  exercises the real native 9P mount/read/SHA-256 proof, checks kernel build
  provenance and includes existing M-series regression tests. Host Python
  socket tests alone cannot establish guest-native TLS evidence.

## Not production-qualified

Still unverified: secure guest credential installation, revocation and
rotation; authenticated **guest** client identities and per-user 9P access
policy; hardened TLS cipher/version policy through full native client source
audit; real separated-VM/external network outage and partition experiments;
rate controls beyond bounded simultaneous test connections; long-duration
load/fuzz/security review; separate hardware and driver certification;
protection against hostile local users able to reach the loopback test
services; public binary release authorization.

The earlier plaintext test path remains intentionally preserved for historical
regression, and must not be described as secure. The recovery exercise toggles
the loopback gateway's upstream test-port reachability; it is **not** a
cross-machine failover or kernel-restart qualification.

Issues #39 and #31 remain open. Source-only experimental CI success does not
authorize production use, physical RAM/CPU extension, or public release.
