<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.2 — Remote data-page cache, not physical RAM extension

`RemotePageCache` holds only bounded 4096-byte **public-data** blocks, pinned to caller-provided SHA256 digests. LRU capacity is at most 64 pages (256 KiB); every remote fetch checks length and digest; cache hits revalidate the hash. Failures are exceptions, **never zeros pretending successful reads** and never unverified fallback data. No sensitive or kernel-critical page can be accepted through the documented API.

End-to-end host CI exercises `RemotePageCache -> authenticated in-process 9P2000 client -> read-only 9P server`. It verifies cache miss/hit, disconnected peers, corruption, eviction and unsafe paths. This is a **host-side test**, not a page fault handler, virtual memory system, swap device, or safe substitute for local physical RAM. Hash checking gives integrity only; data confidentiality and remote availability are not established. Actual remote storage would require TLS, key distribution, revocation and controlled namespace policy.

The prototype has no native kernel memory allocator hooks, sockets, RDMA or external host dependencies. Physical hardware and remote network behavior are unverified.
