<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 7.3–7.4: bounded public-data cache and arithmetic offload

7.3 tests pipe a real 4096-byte public test page through **two** TCP connections: QEMU-facing plaintext socket -> loopback gateway -> TLS 1.3 mutual-authentication upstream peer, then verify a caller-pinned SHA256 with a 2-page capped LRU cache. Cache misses on unavailable remote data **fail**, rather than claiming physical RAM or fabricating a zero page. Contents cannot be kernel-secret, swapped memory or remote physical RAM.

7.4 retains the Phase 6 authenticated `sum_squares` and `dot` pure-job prototype. All integer results are independently recomputed on the caller, meaning **no performance speedup** is claimed. It is intentionally separate from the native Ryzova kernel and no scheduler/RPC primitive is added. Real cross-machine benchmarks, remote execution, cancellation and independent third-party computation verification remain unsupported.

Negative tests cover read-only write rejection, mTLS wrong pin, peer disconnect, multi-client FID separation, bounds and removal of short-lived TLS credentials. CI uses generated certificates only and should never archive private keys.
