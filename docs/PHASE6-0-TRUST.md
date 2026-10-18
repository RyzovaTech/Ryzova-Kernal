<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.0 — Optional remote-resource trust and failure model

This *source-only, host-tested* foundation is intentionally **OFF by default**. `ryzova.remote.trust` authenticates messages between explicitly allowlisted, in-process test peers using HMAC-SHA256, bounded payload quotas, peer-scoped monotonically increasing sequence numbers and expiry checks. Replays, malformed messages, unsupported operations and disabled peers fail closed. The prototype does **not** establish confidentiality: HMAC is NOT encryption.

`LocalAuthenticatedTransport` is intentionally synchronous and in-process; **no TCP/Internet sockets or kernel networking are created here**. Therefore the CI is not proof of distributed network or secure communication between actual machines. No system passwords/keys are stored in the repository; fixed keys in tests are not deployable.

Production prerequisites: mutual TLS 1.3 with pinned/trusted identities, ephemeral key delivery/rotation, disconnect/failure deadlines, per-service ACL, revocation, anti-replay state persistence, replay exhaustion strategy, real transport encryption, confidentiality, audit logging and security review. Never expose kernel credentials or privileged mounts. Keep disconnected local PC workflows fully operational.

Phase 6 branches remain separate from `main` until all Phase 6 phases have passed the agreed acceptance gates and the user authorizes merging.
