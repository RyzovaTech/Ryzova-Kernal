# Guest signal and dynamic application runtime

`compact-linux -j` now runs AMD64 PIE/dynamic programs with an explicitly granted
ELF interpreter and explicitly granted shared libraries. The kernel-side loader
maps the main program and interpreter, supplies program headers/AT_BASE/AT_ENTRY
and native-OS entropy through AT_RANDOM, then executes the unmodified guest
linker. Guest musl performs relocations, constructors, shared-library lookup,
TLS initialization and dlopen/dlsym. There is no host dynamic-linker forwarding.

```
compact-linux -j -x '/lib/ld-musl-x86_64.so.1=/tmp/musl-libc.so' -x '/lib/libflex.so=/tmp/libflex.so' /tmp/dynamic-needed
```

The application arena remains 16 MiB with a 64 KiB initial stack and a 262144-step
default group budget. `-b N` explicitly selects up to 16777216 steps; the
default stays unchanged. PIE uses load bias 0x400000; the granted interpreter uses 0x800000.
Layout overlap, overflow, W+X loads, executable stacks and malformed headers are
rejected. File mappings are private snapshots of explicit immutable grants.
MAP_FIXED can replace only dynamic reservations or anonymous heap pages, not
initial code/stack. Anonymous executable memory and text relocations requiring
W+X remain prohibited. A writable mapping loses permission to become executable.
Existing `-p` and tiny/file ELF profiles retain their strict static loader.

Signals use AMD64 Linux UAPI rt_sigframe/ucontext/sigcontext and an FXSAVE image
for the supported XMM register state. Delivery runs guest handlers on the guest
stack with its red zone preserved, or on a registered alternate stack. The guest
SA_RESTORER routine calls rt_sigreturn; restored addresses, segments, masks, FPU
pointers and permissions are checked before committing context. This is genuine
interrupted guest execution, without host handlers or a fake EINTR-only path.

Implemented: kill/tkill/tgkill inside the invocation; signal masks/pending query;
standard-signal coalescing; bounded FIFO realtime delivery (33 queued entries per
task); nested handlers (8 frames); SA_SIGINFO/RESTART/NODEFER/RESETHAND/ONSTACK;
SIGCHLD; wait termination/stop/continue status; SIGSTOP/SIGCONT/SIGKILL; explicit
SIGCHLD ignore and SA_NOCLDWAIT reaping; alternate stacks and SIGPIPE. Interrupted
blocking I/O/wait can restart under SA_RESTART. Pause/sigsuspend and sleeps return
EINTR when caught signals complete. Exec resets caught actions and alternate
stack, preserves mask/pending signals and the interval timer. Fork starts with
no pending signals and no interval timer. Unsupported CPU instructions and
interpreter access faults still fail the bounded invocation; this does not claim
complete synchronous CPU exception delivery or x87/AVX support.

Time is virtual, not host elapsed or wall time: one logical microsecond per guest
instruction; when all tasks block, time advances to the next guest deadline.
Nanosleep/clock_nanosleep, alarm, real interval timers and rt_sigtimedwait use this
clock. Native libc random bytes come from the explicit OS entropy capability;
there is no deterministic fallback pretending to provide secure random bytes.
Membarrier supports the cooperative interpreter's private expedited ordering;
all guest memory writes are visible before the next interpreted task runs.

Qualification uses unmodified musl 1.2.6, checksum-pinned source, real dynamically
linked ELF programs and selected unmodified static BusyBox ash scripts. Tests
compare against Linux for supported signal/frame/timer behavior and dynamic
outputs, and exercise ASan/UBSan, failed-exec atomicity and mapping denials.
A historical unmodified TinyCC 0.9.27 fixture also compiles freestanding C
inside the guest into `/output`; the exported ELF is then explicitly launched
through a second Compact invocation and compared with Linux. This is selected
compiler qualification without system headers/libc linkage, not a complete SDK.
The compiler test uses an explicit 4194304-step budget.
Native evidence must come from the source-built-kernel gate in
`scripts/phase9_runtime.py`; host reference execution alone is not native proof.

This advances the requested full Compact Linux environment; it does not complete
it. The thread extension is described in [COMPACT-LINUX-THREADS.md](COMPACT-LINUX-THREADS.md).
General sockets/network grants, persistent/general file
mounts, broader instruction coverage, interactive terminals and complete Python,
Git/compiler/toolchain qualification remain unfinished. Do not advertise full
Linux compatibility or physical/operational ARM64 qualification from these tests.

Qualified runtime/helper commit: `ce2b53a3f6c780b28281a66fe29a1b37f0965022`.
The independent source-built kernel passed all 20 signal/timer cases, the
background ash/trap script, three dynamic programs, memory mapping checks and
TinyCC compile/generated-ELF execution. Local regression: 120/120 methods.
The built/installed/independently extracted kernel SHA256 matched. Exact source
and fixture hashes: [local native evidence](validation/phase9-9-local-native.json).
