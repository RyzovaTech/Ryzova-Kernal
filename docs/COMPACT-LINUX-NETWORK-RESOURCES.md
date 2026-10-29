# Explicit outbound TCP resources

The `compact-linux -j` profile can map an exact guest IPv4 address and port to a
caller-selected native TCP resource. A guest connect to that alias uses the
resource backend; another destination cannot select or alter the backing dial
string. An invocation-local listener cannot shadow the mapped route.

```
compact-linux -j -n '10.20.30.40:8080=tcp!10.0.2.2!8000' -x '/lib/ld-musl-x86_64.so.1=/tmp/musl-libc.so' client.elf
```

The native implementation uses Plan 9 `dial`, data files and connection status
files in the caller's namespace. This is a native resource adapter for interpreted
guest instructions; it does not execute a host Linux binary or forward a guest
Linux trap into a host Linux kernel. The Linux-host test harness has a separate
POSIX reference adapter with `guest-IP:port=host-IPv4:port` syntax.

Only explicit routes can reach external resources. IPv4 loopback without a grant
still belongs to the invocation-local stream implementation. Guest-visible local
and peer addresses describe the artificial namespace, rather than revealing the
backing native tuple. Native DNS may resolve a hostname explicitly supplied in a
caller dial string; guest DNS APIs, UDP, IPv6 socket APIs and external listeners
are not implemented.

Each invocation allows four routes and one active connection per route. Fork,
duplication and shared thread file tables retain references to the same resource;
the backend handle closes on the final reference, on full shutdown, or during
invocation cleanup. Closing a connection releases the route for reconnection.
Pending receive bytes support normal read, recv, peek and scatter/gather I/O.
External write-half shutdown and transport option forwarding are unsupported and
return EOPNOTSUPP. Non-default keepalive/nodelay settings cannot silently become
unapplied transport settings on connect. Read shutdown is local to the guest;
full shutdown closes the native resource.

The native adapter checks TCP receive/send queue state before I/O. Write
readiness is conservative: it waits for an empty native send queue and submits
at most 4096 bytes per callback. Native dial has a 1000 ms alarm bound; status,
read, write and close operations have 100 ms alarm bounds. Nonblocking guest
connect reports EINPROGRESS after a bounded backend open; the backend open itself
is not a fully asynchronous dial. No native-speed or latency equivalence is
claimed.

The combined local/external payload quota is 4 MiB. External received payload
also consumes this quota. Guest ring buffers remain 4096 bytes per endpoint.
`-t N` selects an invocation wall budget of 1–10000 ms when routes are granted;
the default is 5000 ms. The clock uses native monotonic fast ticks. The budget is
checked around callbacks and during guest scheduling; one bounded callback and
cleanup can extend completion past the nominal deadline. Idle attempts are
bounded independently of clock progress. A budget failure or a provider contract
violation ends the invocation with status 11 and closes owned handles.

Without routes, time retains the earlier logical-clock behavior. With active
external I/O, observed callback/idle time advances the logical clock, so pending
guest poll/timer deadlines can expire while waiting for a native response. This
is an artificial environment clock, not a promise of full Linux realtime timing.

The embedding API accepts trusted `RyzNetworkResources`/`RyzNetworkOps` callbacks.
Providers must enforce their own per-call bounds; arbitrary blocking C callbacks
cannot be preempted by the interpreter. Invalid readiness bits, impossible byte
counts and backwards/invalid clocks fail closed. The production Plan 9 adapter
and the Linux reference adapter implement the bounded callback contract.

An unmodified pinned BusyBox wget also downloads through the resource adapter,
exports its downloaded file in a filesystem snapshot, and an independent
invocation reloads and reads that file.

Tests cover actual TCP HTTP request/response, finite polling, peek, recvmsg peek,
nonblocking I/O, shared forked descriptors, route reuse, denied destinations,
provider errors and contract failures, stalled peers, clock failures and exact
handle ownership. Selected successful application outputs are compared with
Linux. ASan/UBSan run on both real I/O and provider-contract tests.

The native gate requires eight application invocations plus three unmodified
BusyBox download/persistence invocations, denial without a
route, termination of a real stalled native HTTP request, independent host HTTP
request observations, exact source challenges, fixture hashes and clean exit
records. These establish the tested Plan 9/QEMU TCP path; they do not certify
internet service availability, TLS, operational ARM64 or physical hardware.
