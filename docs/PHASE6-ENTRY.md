<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6 entry — optional remote resource architecture (research plan)

**Current status:** ready to begin isolated Phase 6 engineering research; no remote resources are enabled. Phase 5 experimental source can merge without claiming production app compatibility.

## Goals, ordered by risk

1. **6.0: trust / failure model.** Define authenticated peer identities, remote-resource access control, timeout and reconnect behavior, data integrity, transport TLS policy, network partitions and quota budgets. Remote services disabled by default.
2. **6.1: optional remote storage via 9P.** Start with a read-only remote content namespace, integrity verification and disconnect/retry tests in a sandbox. Never auto-mount privileged host filesystems.
3. **6.2: remote memory as tiered cache, not RAM extension.** Build an experimental bounded page cache with checksums, explicit eviction and writeback, network outage fallback and allocation limits. Remote bytes are not equivalent to deterministic local physical RAM; do not place kernel-critical/secret pages in untrusted remote storage.
4. **6.3: remote compute as delegated tasks, not transparent extra CPU cores.** Start with stateless pure-job offload, resource constraints and deterministic result verification. Remote tasks cannot directly execute privileged kernel instructions or share unrestricted device pointers.
5. **6.4: observability and security.** Audit logs, latency/availability metrics, fault injection, peer revocation, replay defense, data confidentiality and monitoring.
6. **6.5: QEMU/real-network PoC qualification.** Separate functional, failure and attack simulations with optional hardware checks. Remote services remain opt-in and non-release until signoff.

## Non-negotiable boundaries

- No 9front automatic source sync.
- No edits to independent driver-agent implementations as part of Phase 6 infrastructure.
- Keep standard local PC usability when remote services are disconnected.
- No inference that remote memory, CPU or network resources have the speed, behavior or security properties of local resources.
- Project-wide legal, physical hardware and public release gates remain pending.
- Preserve Phase 5 native-Linux-execution technical debt until independently proved by QEMU.
