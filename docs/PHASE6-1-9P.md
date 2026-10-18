<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.1 — Optional read-only 9P2000 storage (local PoC)

A limited **real 9P2000 binary frame codec** with Tversion/Rversion, Tattach/Rattach, Twalk/Rwalk, Topen/Ropen, Tread/Rread, Tclunk/Rclunk and Rerror. The read-only server exposes an in-memory, allowlisted flat file tree; operations like Twrite, create, remove, privileged attach, nested traversal and arbitrary paths are forbidden. Frame sizes max 8 KiB; reads max 4 KiB; file and response budgets bounded.

The client can read content via `LocalAuthenticatedTransport` with HMAC authentication, sequence replay protection and default-disabled `PeerPolicy`. Tests run entirely in-process, **not on a real external 9P host**. The prototype does not mount a 9P filesystem in the native Ryzova Kernel, connect over TCP/TLS, negotiate advanced 9P features, provide credentials/ACL enforcement across machines, or verify an external 9P server's implementation.

Read-only still does not make untrusted remote storage safe: in a production version content needs pinned SHA-256 hashes, encrypted/authenticated network connections, limits, timeout handling, revocation, and kernel namespace sandbox review. Phase 6.2 separately demonstrates hash checking at the cache boundary. No user files or remote network are contacted by CI.
