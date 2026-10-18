<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.3 — Delegated pure computing, not additional CPU cores

The allowlisted prototype accepts two deterministic, bounded **integer-vector** tasks: `sum_squares` and `dot`, each with at most 256 elements and absolute element value at most 1,000,000. No Python `eval`, source code, shell commands, OS processes, executable binaries, device memory or privileged kernel interface is made available to the service. The server limits jobs by quota; input bytes are bounded; requests/responses travel through the authenticated *in-process* transport from Phase 6.0 and a response echoes a SHA256 request identifier.

Crucially, the client **independently recomputes** the result rather than assuming the peer's claim is correct. This verifies malicious/wrong mock responses, but it also means the test yields **no CPU performance advantage**. It illustrates an auditable pure offload protocol, not real remote compute, not a multiprocessor scheduler and not an extension of local CPU cores. Peer revocation, robust TLS, scheduler integration, external machines, cost/latency benchmarks and distributed execution failure recovery remain unfinished.

Tests cover legitimate output, invalid job names/parameters, oversized vectors, signed integer bounds, tampered remote output, disabled connections, simulated outage and job exhaustion.
