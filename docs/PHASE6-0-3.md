<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6.0–6.3 developer prototype status

This is an **experimental host-only, in-process** optional remote-resource foundation. All features are **OFF by default**. The code is written under `ryzova/remote/` and deliberately does not change 9front/Ryzova kernel code, native driver source, device firmware or branch-protection rules.

| Stage | Implemented in prototype | Not implemented |
| --- | --- | --- |
| **6.0** | HMAC-authenticated allowlisted local test peer, replay and expiry checks, quotas | TLS, real network transport, secure key exchange/revocation |
| **6.1** | Read-only minimal 9P2000 wire frames and in-memory synthetic service | Native Ryzova 9P mount or external 9P server |
| **6.2** | Pinned-SHA256 bounded LRU 4096-byte public-data cache with fail-closed outages | Extra physical RAM, swap/page faults, kernel cache |
| **6.3** | Allowlisted stateless integer-vector pure jobs with deterministic verification | Real remote machines, more local CPU cores, speedup |

A practical local proof is executed with:
```sh
python3 -m unittest discover -s tests -p 'test_phase6*.py' -v
python3 scripts/phase6_status.py
```
The CI uses Python 3.11 and 3.12, archives a JSON provenance report and never connects to actual remote computers or publishes binaries. Existing AMD64 native QEMU build verifies only no baseline kernel regression when independently triggered. Treat Phase 6.0–6.3 as **host prototype research**, not actual remote-resource support.

**Next work:** Phase 6.4 security/recovery and observability, followed by Phase 6.5 actual TLS opt-in peer/network/QEMU proof with failure injection and native kernel integration. No Phase 6 merge until user-authorized full series completion.
