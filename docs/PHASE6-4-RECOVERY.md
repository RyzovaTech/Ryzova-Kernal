<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.4 — Failure containment and telemetry foundation

The default-disabled `RemoteCircuit` wraps the Phase 6.0–6.3 request transport with bounded requests/replies, a failure counter, a circuit breaker, cooldown and single recovery probe. A health recovery must be observed before the breaker clears. A failed request returns a *failure*, never unverified data or a pretend successful local RAM read.

Telemetry stores only allowlisted operation labels and generic event categories; no payloads, exception text, passwords, peer keys or remote contents. Event history is size-limited. Tests cover failure trip/recovery, disabled services, slow calls, oversized responses, fake remote errors, counters and negative policy settings.

**Limits:** `RemoteCircuit` detects a slow synchronous call only *after* it returns; it cannot interrupt arbitrary host code. Real TCP/TLS transport sets socket timeouts and handshake limits in Phase 6.5. This is not a kernel scheduler, page-fault handler, real remote hardware, or recovery from untrusted machine failure in the native Ryzova guest. The service is strictly optional.
