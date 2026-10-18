<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 7.0–7.2 native QEMU 9P secure-gateway threat boundary

A disposable source-built Ryzova AMD64 QEMU guest mounts a **public-only** 9P2000 share at `tcp!10.0.2.2!15640`. Guest QEMU user-mode TCP reaches a loopback gateway. The gateway opens an authenticated **mutual TLS 1.3** session to a separate loopback 9P server and verifies the trusted peer leaf certificate SHA256. The peer requires and pins the gateway's mTLS client certificate, then serves read-only 9P messages. It allocates a fresh per-connection FID namespace. TLS keys and certs are freshly generated at test run time; they are not stored in Git or uploaded as artifacts.

**Trust boundary (critical):** only the gateway ↔ remote 9P peer hop is encrypted/authenticated. The Ryzova guest ↔ gateway hop is still *unencrypted and unauthenticated* for this isolated CI experiment. The gateway runs on the Linux CI host, not in the Ryzova kernel. No assertion is made that native Ryzova has a TLS client, that certificate credential isolation holds against a compromised host, or that this is safe for user/private resources.

The gateway rejects unsupported/write operations, bounds 9P frames to 8192 bytes, validates transaction tags, has connection timeouts and **no automatic plaintext fallback**. The peer itself rejects writes and unauthorized attach paths. A malicious CI-host gateway or malicious guest could still access the in-memory public test fixture; the real-world credential/privilege boundary is unverified. No extra RAM, CPU cores or external-machine throughput is provided.

7.2 tests use separate TCP listeners and ephemeral per-client 9P FID tables, fault-injected unavailable peer and mismatched certificate pins. The physical-network/remote-VM acceptance gate remains open (Issue #39).
