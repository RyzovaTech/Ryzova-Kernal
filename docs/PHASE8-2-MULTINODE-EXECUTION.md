<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 8.2.1–8.2.4 — Real isolated multi-node transport, discovery and dispatch

This research branch stacks on the **unmerged Phase 8.2.0 control-plane
prototype**, PR #56. It must NOT be merged into `main` ahead of a verified
and merged 8.2.0 base. All source/build/driver regressions remain mandatory.

## Option B architecture: one logical Ryzova environment, many real nodes

An opt-in coordinator automatically selects eligible resources for bounded,
side-effect-free jobs. The long-range plan encompasses file/storage,
AMD64/ARM64 compute, GPU, cache, network and device services in a common
9P-oriented namespace with explicit ownership/permissions and failure
isolation. It **does not merge physical RAM, CPU cores or GPUs into a local
shared-memory SMP computer.** The unified namespace inventory and scheduler
from 8.2.0 are control-plane prototypes, not kernel integrations.

### 8.2.1 — Real multi-node transport and 9P access

`ryzova/remote/phase8_multinode.py` provides:
- Separate long-running node-service TCP processes that require TLS 1.3
  **mutual** certificate verification and independently pinned SHA-256 DER
  leaf fingerprints. No plaintext fallback, empty authorization or free-form
  command dispatch.
- Standard bounded read-only 9P2000 requests transported in length-limited
  TLS JSON envelopes to the preexisting `Native9PConnection` server.
  Each TLS session receives a fresh FID table; only a small public `probe`
  fixture can be opened/read, and privileged/write operations are denied.
- Two fixed, preinstalled pure compute operations: `sha256` and
  `byte_count`. Inputs are limited to 4096 bytes. No shell, subprocess,
  arbitrary program or code upload is exposed by the node service.

`scripts/phase8_multinode_netns.py` sets up two **Linux network namespaces**
with individual veth interfaces/subnets and separate Python server PIDs.
The host controller reaches them over different virtual network links.
It requires Linux root/iproute2 and runs only in an isolated CI runner;
it fails instead of silently skipping if netns privileges are unavailable.

**Evidence type:** two independent network namespaces/processes, *not* two
QEMU virtual machines or physical computers. Running the script in Actions
and checking its output are required before claiming 8.2.1 verified.

### 8.2.2 — TLS-bound trusted node discovery

`RemoteNode.discover` performs a real client-authenticated TLS handshake,
validates the server's TLS protocol, X.509 hostname and pinned DER leaf,
asks for a declarative bounded `NodeOffer`, checks the announced ID and pin
match the verified channel, then invokes the trusted `ResourceRegistry`
admission policy. Identity cannot be established from JSON fields or a
caller-supplied `authenticated=True` flag.

This is an ephemeral CI certificate model. Static test certificates and
allowlists are not production PKI, authorized cluster provisioning, OCSP,
secure revocation distribution, delegated user identity or native kernel ACL.
The registry uses fixed leases/generations and conservative quarantine;
a quarantined node is not silently reintroduced without a freshly
provisioned registry. No public listeners are exposed by the CI fixture.

### 8.2.3–8.2.4 — Real remote pure compute and automatic placement

`RemoteNode.compute` sends only approved public-data operations over
the *verified TLS socket* to separate node processes; it independently
checks the returned result. The Phase 8.2 coordinator from PR #56 admits
only opt-in workloads, checks architecture, bounded slots, lease and
payload, and deterministically spreads successive jobs across eligible
nodes. Failed nodes are quarantined and a second eligible node may complete
an idempotent task (at most two attempts). Test evidence includes the
first node's network partition, failover to the second node and explicit
node re-admission after the link is restored.

Scheduling real remote *pure service* requests is **not** transparently
migrating arbitrary desktop threads/processes or safely executing arbitrary
remote binaries. No Ryzova-native scheduler, VM guest identity propagation,
GPU compute driver or real distributed 9P namespace mount is introduced.
The guest's previous native AMD64 QEMU TLS/9P tests must stay green.

## Tests and merge gates

- `tests/test_phase8_multinode.py`: distinct real TLS socket services,
  mTLS client pin/hostname, 9P file integrity, cross-node deterministic
  placements, stale lease/generation, forged offer ID, unrelated client
  certificate rejection, write denial, oversize/command denial, per-session
  FID isolation and simulated node shutdown/failover.
- `scripts/phase8_multinode_netns.py`: two *actually separate* Linux network
  namespaces, 9P/TLS read hashes, automatic placement across node processes,
  network partition with fallback and explicit recovery.
- `.github/workflows/phase8-multinode-transport.yml`: Python 3.11/3.12
  local TCP tests and mandatory Linux network-namespace job.
- Existing source-built AMD64 QEMU, Phase 7/8.1 TLS/9P and M-series driver
  checks remain mandatory for exact PR-head acceptance.

A successful host integration test is NOT native guest distributed-compute
certification. A later phase must run independent Ryzova VM guests,
authenticated native namespace management, a proper sandboxed computation
API, capability delegation and real hardware trials with long-run fault
injection.

Never re-enable automated 9front syncing, touch independent driver-agent
files or claim production readiness; leave Issues #31/#39/#36 open.
