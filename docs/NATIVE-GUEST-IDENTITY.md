<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Native guest mTLS identity: experimental acceptance path

An opt-in TLS 1.2 listener now requires an authenticated client certificate,
checks the live SSLSocket leaf against an independently configured SHA-256
pin, and binds the accepted session to `ryzova-qemu-guest`. Client-supplied
9P `uname`, headers and boolean assertions do not establish this identity.
Missing certificates, untrusted leaves and mismatched pins cannot forward 9P.
The existing server-authentication-only research ingress remains separate.

The source-built AMD64 QEMU workflow provisions a disposable RSA certificate
and private key, imports the private key into the guest's existing factotum
agent, and invokes native `tlsclient -c` to prove possession during the TLS
handshake. It then mounts/reads the public 9P fixture and independently checks
its SHA-256. `phase8-guest-identity.json` requires both native serial evidence
and host live client-authentication/frame counters. Host-only tests or echoed
shell commands cannot satisfy the native acceptance gate.

Credentials are test-only, created in an ephemeral fixture, delivered through
the disposable slirp/loopback harness, removed from guest disk after import,
and excluded from all uploaded CI artifacts. Host credential files are deleted
in both normal cleanup and the workflow's always-run cleanup. The native
source HTTP server binds loopback rather than a public interface. This is
not production credential provisioning, hardware-backed identity, revocation,
rotation or a private multi-tenant environment.

Guest identity is verified at the ingress. It is not propagated as a verified
identity over the distinct gateway-to-peer TLS 1.3 session, and it does not
implement per-human-user ACLs. Public fixtures, loopback services and existing
session/frame limits remain. Native proof is established only when the new
current-source QEMU workflow actually passes; implementation and host tests
alone are insufficient. Physical hardware and release gates remain open.
