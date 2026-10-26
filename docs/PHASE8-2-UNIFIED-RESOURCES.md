<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 8.2 — Ryzova Unified Distributed Resource Architecture (Option B)

## User-approved architecture decision

Ryzova is not being developed as a "remote RAM" or "remote storage only"
feature. The intended destination is a **single logical Ryzova operating
environment** backed by independently owned AMD64 and ARM64 machines:
namespace-visible storage, CPU services, bounded data caches, GPU services,
network services and selected devices. When the user explicitly enables
resource federation, a permission-aware coordinator should select the
appropriate healthy nodes automatically and distribute *eligible* workloads.

Classic Plan 9 concepts preserved: per-process namespaces, 9P file services,
explicit CPU service boundaries and independent nodes. Option B extends this
with capability admission, policy-aware placement, failure isolation, and
eventually trusted cross-node workload control. Automatic selection must not
silently turn a remote CPU into a physical local processor, remote page cache
into ordinary RAM, remote GPU into a local GPU driver, or networked 9P files
into an intrinsically consistent local filesystem.

## Proposed logical namespace (NOT mounted yet)

    /cluster/
      nodes/<node-id>/
      storage/
      compute/
        amd64/
        arm64/
      gpu/
      devices/
      network/
      cache/
      jobs/

The first Phase 8.2.0 module records the proposed node namespace name only.
No read/write mount or service endpoint is attached. Per-process namespaces,
device ownership, permissions, remote-user delegation, and stable namespace
mapping require separate engineering and real QEMU evidence.

## Phase 8.2.0 — merged Phase 8.1 baseline -> new research branch

Code: `ryzova/remote/phase8_cluster.py`
Tests: `tests/test_phase8_cluster.py`
CI: `.github/workflows/phase8-unified-resources.yml`

Host-only, disabled-by-default reference *control plane*:

- Admin-provisioned allowlist up to 16 logical nodes with static certificate
  fingerprint metadata; immutable offers describe declared compute, storage,
  cache, GPU and device roles and AMD64/ARM64 architectures.
- Bounded leases, generation checks, quotas, active slot reservations and
  quarantine of failing nodes. Expired/offline nodes cannot be selected.
- Opt-in automatic deterministic compute placement using spare capacity,
  latency, permitted architecture, payload size and explicit remote consent.
- Failover across different trusted test adapters only for two predefined
  pure, idempotent *public-data* operations: SHA-256 and byte counting.
  No arbitrary code, process spawn, shell, filesystem access or network socket.
- A tested local-node fallback when a simulated remote adapter fails.
- Roles other than compute are discovery descriptors, **not operating
  services**; no actual remote storage, GPU or device execution in this patch.

### Trust boundary (critical)

A SHA-256 string included in a node offer or passed as a "presented
fingerprint" is **not proof** of a verified TLS session. This reference
model is called only from trusted, in-process test harnesses. It must not
accept network-supplied offers or attach remote executors without a new
mutually authenticated transport adapter that derives peer identity directly
from the verified TLS session, enforces node authorization and binds each
lease to that identity. In-process handlers in this prototype are trusted
test adapters, not a distributed execution security sandbox. Results from a
malicious remote compute server cannot be trusted based merely on a
well-formed digest; future work must validate output and origin.

No actual multiple-VM/machine networking or native guest coordinator is
implemented or verified by the Phase 8.2.0 tests. The existing source-built
AMD64 QEMU/TLS/9P tests from Phase 7/8.1 remain independent and must pass.
Even after this PR passes CI, the automatic scheduler will be a **host
research prototype**, not a demonstrated multi-machine RyzovaOS computer.

## Phase 8.2 implementation gates

- **8.2.0** — explicit architecture and fail-closed research resource
  admission, deterministic scheduling and pure-task adapter tests (this PR)
- **8.2.1** — two isolated network namespaces or QEMU VMs, actual separate
  listeners and real authenticated 9P file reads with SHA256 source evidence;
  no loopback-only evidence presented as a physical remote machine
- **8.2.2** — transport-bound node discovery and certificate identity,
  lease renewal/revocation, per-process authorization and namespace
  lifecycle, with negative network/identity tests
- **8.2.3** — bounded, authenticated remote *pure compute service* protocol,
  sandbox, workload/result integrity, cancellation and audit evidence
- **8.2.4** — automatic multi-architecture capacity-aware scheduler with
  true cross-machine job dispatch, placement telemetry and limited retries
- **8.2.5** — partition, reboot, timeout, duplicate execution, stale lease,
  key rotation, inconsistent storage, failback and isolation tests
- **8.2.6** — only then consider opt-in native Ryzova guest namespace and
  scheduler integration under exact-head source-built QEMU validation
- **8.2.7** — threat review, reproducibility, hardware pilot and explicit
  non-production/production release decisions

Physical CPU cores do not combine into a shared SMP machine. Shared
memory/address-space and cache-coherence semantics are not implemented;
remote data caching stays bounded. Automatic scheduling can select only
workloads deliberately written to tolerate distributed execution. Legacy
AMD64 functionality must not depend on an always-present network.

## Project boundaries

- Do not enable upstream 9front auto-sync.
- Do not modify the independent M-series/D-series driver agent source.
- Do not claim hardware model counts, physical RAM expansion, physical core
  extension, guest-to-peer end-to-end mTLS, remote per-user ACL security,
  Linux/Windows/macOS binary compatibility or production certification.
- Keep release/hardware/guest execution gates #31, #39 and #36 unresolved.
- Merge only after **exact-head CI** passes, including native AMD64 QEMU,
  relevant Phase 7/8.1 regressions and existing driver acceptance workflows.
