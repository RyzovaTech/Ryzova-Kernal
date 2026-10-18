<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 6 native QEMU experimental 9P handoff

The user requested an actual Ryzova native-kernel remote resource proof after Phase 6.0–6.5 host prototype integration.

The **new required gate** is the Phase 3 native AMD64 source-built QEMU job, now extended with a read-only 9P2000 TCP fixture on the Linux CI host. Its guest runs `srv -nq tcp!10.0.2.2!15640 ryzova6`, then `mount -n /srv/ryzova6 /n/ryzova6`, reads a commit-specific public data file from the native 9P mount, and computes its own SHA256. The host verifies exact challenge and digest from standalone serial-output lines, plus actual 9P frame traffic. Without the correct guest output, the CI **fails**.

This demonstrates an actual QEMU guest/host filesystem connection, **not** native integration of the Python TLS prototype (9P mount here deliberately uses unauthenticated plaintext inside isolated CI), real Internet remote peers, remote RAM or remote CPU. Secure guest TLS, per-peer credentials and integration with any Ryzova user-space system service require future work and external review.

Do not enable this fixture in general production boot settings or ship its unauthenticated server. Issue #39 remains open until real authenticated peer and physical testing.
