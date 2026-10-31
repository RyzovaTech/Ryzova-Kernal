<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# CLX-05 — First bounded IPv6 socket increment (NOT full networking)

The original Ryzova compact Linux syscall service can now open AF_INET6
(10), SOCK_STREAM (1), TCP (6), and bind/connect/listen/accept on **guest
local ::1 or :: only**. 28-byte Linux sockaddr_in6 values are parsed;
nonzero flowinfo/scope, off-link routes and external IPv6 paths are rejected
with explicit Linux-style errors. The descriptor, 32-socket table, 16-fd
limit, 4-MiB traffic quota, queue and existing timeout/cleanup semantics
are inherited. TCP_NODELAY remains a bounded per-socket option.

An unmodified native AMD64 socket fixture is exercised under host Linux
and the Ryzova interpreter with byte-for-byte response comparison, including
forked accept/send/recv and independent negative off-link tests. This adds
a real IPv6 **loopback** API, not a second-machine or production network
stack. It does **not** implement DNS, UDP datagrams, real IPv6 routes,
host IPv6 resource grants, guest TLS certificate/hostname verification,
or NET-PEERS/TLS-GUEST CLX-05 acceptance.
