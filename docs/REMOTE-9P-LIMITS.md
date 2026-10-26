<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Research 9P state validation and listener budgets

Ryzova-owned host Python research services now stage each native 9P request
against a bounded copy of connection state. FIDs, open flags, negotiated
version state and msize are committed only after the entire request and
response have been validated. Rejected/truncated requests and trailing bytes
leave the prior connection state intact.

## Per-listener limits

`Native9PTCPServer`, `Local9PTLSGateway` and `SecureReadOnly9PPeer` use
`BoundedTCPServer` from `ryzova/remote/listener_limits.py`:

| Constructor option | Default | Accepted range | Effect |
| --- | --- | --- | --- |
| `max_sessions` | 8 | 1..32 | Reject excess sockets before handler-thread creation, including pending TLS handshakes |
| `max_frames_per_session` | 256 | 1..4096 | Close the connection after the attempted frame budget; gateway-denied writes also consume budget |
| `max_fids` (TCP server and peer only) | 256 | 1..4096 | Reject new attach/walk allocations when the per-connection FID table is full |

Booleans, non-integers and out-of-range limits are rejected before listening.
Clunk releases a FID, and a valid version renegotiation clears the FID table.
In-place walks do not consume an additional FID. The staging copy is bounded
by the same FID budget. Limits are per listener/connection, not a global
quota across all services.

Admission slots are released after disconnect, TLS failure, protocol failure,
quota exhaustion and thread-start failure. Counters expose `active_sessions`,
`peak_sessions`, `rejected_connections` and `frame_quota_closes` under the
listener's metrics lock. Existing socket I/O timeouts remain in effect;
they are inactivity timeouts, not absolute connection-lifetime deadlines.
Quota closure never transparently retries or replays a request. A caller
must explicitly establish a new TLS/9P session after closure.

The existing guest TLS 1.2 ingress retains its own admission/frame quotas.
Direct access to the loopback TCP gateway or peer no longer bypasses
admission/frame budgets. Servers still bind only `127.0.0.1` and serve only
the public `probe` fixture. These limits do not introduce authenticated guest
identities, production access control, hardware qualification, or a release.

## Regression checks

- `tests/test_phase6_native9p.py`: malformed and truncated version, attach,
  walk, open and clunk requests preserve state; rejected attach cannot be
  opened; FID exhaustion and reclamation.
- `tests/test_phase7_secure_bridge.py`: direct real-socket admission and frame
  exhaustion for all three listeners, gateway denial budgets, recovery after
  disconnect/failed handshake, thread-start failure, and invalid limits.
- Existing Phase 7 ingress and Phase 8 TLS-bound policy tests must remain
  green. Native source-built AMD64 QEMU CI remains a separate acceptance gate.

Origin: newly authored, AI-assisted Ryzova-specific changes under the existing
AGPL-3.0-only file policy; no upstream 9front or driver source modifications.
