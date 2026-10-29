# Invocation-local Linux stream sockets

The `compact-linux -j` profile implements stream sockets inside the invocation's
resource namespace. Guest instructions and guest memory drive the connections.
There is no forwarding to a host Linux socket or process. The namespace is shared
by the invocation's forked processes and threads, and discarded at invocation
end. Two independent invocations cannot reach each other's sockets.

Supported domains are AF_UNIX abstract addresses and AF_INET loopback addresses.
AF_INET here identifies an isolated virtual stream endpoint; this does not claim
an external TCP stack. Non-loopback addresses are rejected with ENETUNREACH.
Filesystem Unix socket paths, external routes, DNS, IPv6 and datagrams are not
implemented. External resource grants will require a separate transport backend;
no such backend is implied by this implementation.

The stream API includes socket/socketpair, bind/listen/connect, accept/accept4,
getsockname/getpeername, read/write/readv/writev, sendto/recvfrom without an
outbound destination, sendmsg/recvmsg without ancillary messages, shutdown,
nonblocking operation, descriptor duplication and fstat. Message flags support
peek, don't-wait and no-SIGPIPE. MSG_WAITALL and descriptor passing are explicitly
unsupported. Common socket-option values have bounded guest state; this does not
claim real-time TCP keepalive probes or an external TCP congestion algorithm.

Read and write ends close independently. Buffered bytes remain readable after
peer write-shutdown or final descriptor close; writes to a closed peer produce
EPIPE and guest SIGPIPE unless suppressed. Description references, shared thread
file tables, fork/exec and final cleanup determine endpoint lifetimes. A pending
accepted endpoint belongs to its listener until accept creates a descriptor;
closing a listener releases that queue. Failed socketpair creation releases its
partial allocation. Accept validates guest output pointers before consuming its
queue, a deliberate bounded-profile difference from Linux error-side effects.

Poll supports readiness, finite logical deadlines and indefinite waits. Finite
deadlines advance the invocation's logical clock when no task can run. Caught
signals interrupt poll with EINTR even under SA_RESTART. Guest network traffic
never blocks the host on real network I/O.

Limits are 32 endpoints, 16 descriptors per shared descriptor table, 8 pending
connections per listener, a 4096-byte receive ring per endpoint, 16 message iovecs
and 4 MiB of cumulative transferred payload per invocation. Partial writes and
backpressure retain stream ordering. Limits and error-side effects are tested as
explicit guest policy; they are not compared to unrelated host resource limits.

Tests cover 26 raw syscall workloads plus a dynamically linked musl pthread HTTP
application. Eighteen raw workloads and the HTTP application are compared with
Linux. An additional abstract Unix bind comparison runs on an unrestricted Linux
runner; this local sandbox denies host Unix bind, so only that local reference
case is skipped. Guest Unix sockets still execute in the regular and sanitizer
suites. Byte-order/rotate instruction tests cover the instructions needed by
musl htonl/htons, register width and defined flags.

`scripts/phase9_sockets.py` extends the fresh native source-build gate. It requires
exact source challenges, fixture SHA256s, all workload markers and clean exit
records. A host-only test run does not qualify the native kernel. CI uploads the
native report as `artifacts/phase3/phase9-linux-sockets.json`.

See [full environment status](COMPACT-LINUX-STATUS.md) for remaining work.
