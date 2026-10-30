# Full Compact Linux status

**Incomplete.** The bounded AMD64 application environment has reviewed source
integration, including the qualified CLX-02 filesystem profiles. Passing its
tests does not establish compatibility with arbitrary Linux applications. Full
Linux and public-binary release gates remain separate.

| Area | Implemented scope | Remaining for a general environment |
| --- | --- | --- |
| Loading | Selected static ELF, PIE, explicit musl interpreter/library grants | More loaders, libraries, relocation and ISA workloads |
| Processes | Fork/vfork/exec/wait, pipes, bounded process groups | Broader process/session/resource APIs |
| Threads | Cooperative shared-memory clone, musl pthreads, TLS, selected futex/robust operations | More clone profiles, priority inheritance, broader concurrency workloads |
| Signals/time | Guest frames, masks, pending queues, selected logical timers | More timer APIs and synchronous exception coverage |
| Files | Managed root, explicit live directory capabilities, per-app views/revocation, FLEXFS4 persistence; guest symlinks, hardlinks and shared file maps | Broader POSIX semantics on native mounts, metadata, durability and measured developer budgets |
| Networking | Local streams and explicit mapped outbound TCP resources | Guest DNS, UDP, IPv6 socket ABI, external listeners and wider socket APIs |
| Applications | Selected unmodified BusyBox/musl workloads; freestanding TinyCC compilation; musl pthread HTTP | Full Python, Git, compiler/SDK and interactive workloads |
| Terminal/graphics | Bounded output callbacks and isolated input snapshots | Interactive terminal, PTY, graphics/audio/device APIs |
| Architecture/hardware | Source-built AMD64 QEMU qualification; selected ARM64 source cross-compilation | Operational ARM64 boot/I/O/SMP and physical lab qualification |

Application breadth must be proven with named, versioned workloads, reproducible
fixtures and explicit resource grants. Unsupported operations must fail rather
than returning a fabricated application result. The declared live-mount profile
is native-qualified. Broader filesystem/network APIs still require implementation
and native tests; relabeling existing passing tests does not supply them.

The socket extension is described in
[COMPACT-LINUX-SOCKETS.md](COMPACT-LINUX-SOCKETS.md); explicit file persistence is in
[COMPACT-LINUX-PERSISTENCE.md](COMPACT-LINUX-PERSISTENCE.md). Outbound resources are in
[COMPACT-LINUX-NETWORK-RESOURCES.md](COMPACT-LINUX-NETWORK-RESOURCES.md). Earlier native evidence and
limitations remain attached to their exact historical source commits.

Symbolic-link path semantics and version 2 snapshots are described in
[COMPACT-LINUX-SYMLINKS.md](COMPACT-LINUX-SYMLINKS.md).

Shared inode names and version 3 snapshots are described in
[COMPACT-LINUX-HARDLINKS.md](COMPACT-LINUX-HARDLINKS.md).

Shared mappings and guest EOF faults are described in
[COMPACT-LINUX-SHARED-MAPPINGS.md](COMPACT-LINUX-SHARED-MAPPINGS.md).

The finite developer V1 completion contract and CLX-01–CLX-08 phase plan are in
[COMPACT-LINUX-V1-PLAN.md](COMPACT-LINUX-V1-PLAN.md); machine acceptance IDs are in
[linux-v1-plan.json](../ryzova/compact/linux-v1-plan.json). Regression counts do not
close those application acceptance gates.


CLX-02 is now qualified for the declared bounded filesystem profiles: managed
root, explicit live directory capabilities, narrower application views,
revocation of open fds and independent restart/recovery. FS-ROOT, FS-ISOLATION
and FS-PERSIST have evidence in [the acceptance record](validation/compact-linux-v1-phase2-acceptance.json).
Linux V1 is still incomplete; CLX-03 memory/process/budget work is next. Native
live mounts retain the documented POSIX and durability limitations.
