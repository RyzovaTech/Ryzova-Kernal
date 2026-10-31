<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# CLX-05 — Bounded local UDP datagram compatibility research

In addition to bounded IPv6 ::1 TCP, Ryzova user-space Linux can now
create AF_INET/AF_INET6 SOCK_DGRAM sockets (protocol UDP 17), bind an
in-namespace loopback address, sendto/recvfrom, use MSG_PEEK and connected
read/write. A separate four-packet queue is maintained per socket, with
a combined 4096-byte queue budget, a 4096-byte maximum per datagram,
a 4-MiB aggregate guest network transfer limit and explicit source
sockaddrs. Truncated reads consume one whole datagram; peeks do not.
Existing TCP stream semantics are unchanged. Off-link datagrams are
rejected without host callbacks, network discovery or arbitrary routing.

A source-built unmodified AMD64 fixture exercises IPv4 and IPv6 UDP
and byte-for-byte compares local responses to native Linux. Local
UDP loopback is NOT a real separate-peer UDP exchange. DNS, remote
IPv6, complete UDP error/ICMP behavior, unmodified Python/Git TLS,
and CLX-05's NET-PEERS/TLS-GUEST gates are still OPEN.

## CLX-05 — TCP/UDP port namespaces

Bound local TCP and UDP sockets now use **separate**, type-specific port
occupancy checks, matching Linux's independently allocated transport port
spaces while retaining duplicate-bind rejection within the same protocol.
A source-built unmodified AMD64 socket fixture verifies both directions
(native Linux and the Ryzova interpreter), plus denial of duplicate TCP/UDP
binds and post-close reuse. This preserves the prohibition on off-link
transmission and does not qualify DNS, real inter-node UDP, guest TLS, or
CLX-05 release acceptance.
