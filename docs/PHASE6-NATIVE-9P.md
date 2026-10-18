<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6 native 9P bridge — Ryzova QEMU guest/host integration

**Goal:** Unlike earlier Phase 6 host-only research and the Phase 3 RAMFS probe, this is intended to run a *fresh source-built Ryzova AMD64 kernel* and mount a TCP 9P2000 test service offered by the disposable Linux CI host.

The native kernel's built-in Plan 9 9P support is used **without patching or replacing the kernel's syscall/driver code**. The host starts a minimal read-only 9P2000 TCP server bound to localhost port 15640. QEMU user-network guest maps the host gateway to 10.0.2.2. From the fresh kernel's 9front `rc` guest, the test executes `srv -nq tcp!10.0.2.2!15640 ryzova6` then `mount -n /srv/ryzova6 /n/ryzova6`, reads `/n/ryzova6/probe` and computes a guest-side SHA-256 via `sha1sum -2 256`. The file contents embed the exact current Git SHA to prevent stale boot/log confusion. CI compares against a host-calculated SHA-256 and checks that the server actually processed multiple 9P frames. Output evidence is `artifacts/phase3/phase6-native-9p.json`, and the runner fails closed if data/mount/hash does not match.

**Security:** The `srv -n` / `mount -n` commands bypass Plan 9 authentication **ONLY for a disposable, public, read-only QEMU fixture**. TCP connection is not encrypted; there is NO guest TLS client, peer CA validation or production security, and the server is accessible to the VM gateway only in the disposable test topology. No credentialed mounts, host user files, kernel secrets, writes, OS binary publication or Internet access are needed. NEVER deploy this server outside isolated CI.

This demonstrates an end-to-end *remote-style 9P network filesystem* connection between two isolated systems (QEMU guest kernel and Linux CI host); it does **not** demonstrate two physical machines or real external Internet peers. It is not a remote RAM subsystem or extra CPU core support. The previous Python TLS 1.3 / HMAC prototypes still run separately on the Linux host and are **not yet the guest's native transport**.

**Verify:** The Phase 3 native-build GitHub Actions workflow must be green on the exact integration commit. A host-only mock of the serial log is insufficient. The 9P service host code additionally has TCP unit tests for 9P message parsing, stat, fid isolation and denied writes.
