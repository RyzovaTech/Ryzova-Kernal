<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 7.5–7.6 — Experimental QEMU gateway and research closeout

The executable Phase 7.5 proof is **not just a host-side simulation**. The existing GitHub native source build boots Ryzova AMD64 in QEMU, mounts `tcp!10.0.2.2!15640`, reads commit-bound public 9P data, and calculates SHA256 **inside the guest**. The CI host's gateway authenticates to an upstream read-only 9P peer using TLS 1.3 **mutual certificates**, independently checking the server leaf SHA256 while the peer checks the client leaf SHA256. A per-session FID server and read-only rejection are enforced. The gateway records actual forwarded frames and successful pinned mTLS sessions; both evidence and guest SHA are required to pass.

**IMPORTANT — still no native guest TLS:** QEMU guest → CI host gateway is plaintext, without authentication. Only gateway → upstream peer is TLS 1.3 secured. Both endpoints are loopback services on one CI Linux host. No separate physical machine, external network, general user filesystem, production PKI, native RAM/CPU migration, or public release has been certified. Test-only certificates and keys are generated in temporary directories at runtime; the evidence artifact contains only counters and hashes.

7.6 `scripts/phase7_secure_closeout.py` fails closed if the exact source SHA, independently verified Ryzova compiled/installed/extracted kernel provenance, real guest 9P mount/read/SHA, mTLS session counts, 9P frame forwarding, or blocked public release statements disagree. It is executed after the actual QEMU job, not substituted with unit tests.

**Phase 7 development source may merge as an experimental research integration** only when native QEMU and all regression CI are green. This does NOT close real external-peer integration Issue #39 or release qualification Issue #31. Native guest TLS, peer revocation, isolated networks and cross-machine fault benchmarks remain mandatory for future production support.
