# Full Compact Linux status

**Incomplete.** The bounded AMD64 application environment is implemented in
cumulative draft branches. Passing its tests does not establish compatibility
with arbitrary Linux applications. No automatic merge or full Linux release is
authorized by these changes.

| Area | Implemented scope | Remaining for a general environment |
| --- | --- | --- |
| Loading | Selected static ELF, PIE, explicit musl interpreter/library grants | More loaders, libraries, relocation and ISA workloads |
| Processes | Fork/vfork/exec/wait, pipes, bounded process groups | Broader process/session/resource APIs |
| Threads | Cooperative shared-memory clone, musl pthreads, TLS, selected futex/robust operations | More clone profiles, priority inheritance, broader concurrency workloads |
| Signals/time | Guest frames, masks, pending queues, selected logical timers | More timer APIs and synchronous exception coverage |
| Files | Bounded writable tree, explicit immutable filesystem persistence and input/output/library snapshots; guest symlinks and shared-inode hardlinks | General live persistent mounts, broader metadata and filesystem operations |
| Networking | Local streams and explicit mapped outbound TCP resources | Guest DNS, UDP, IPv6 socket ABI, external listeners and wider socket APIs |
| Applications | Selected unmodified BusyBox/musl workloads; freestanding TinyCC compilation; musl pthread HTTP | Full Python, Git, compiler/SDK and interactive workloads |
| Terminal/graphics | Bounded output callbacks and isolated input snapshots | Interactive terminal, PTY, graphics/audio/device APIs |
| Architecture/hardware | Source-built AMD64 QEMU qualification; selected ARM64 source cross-compilation | Operational ARM64 boot/I/O/SMP and physical lab qualification |

Application breadth must be proven with named, versioned workloads, reproducible
fixtures and explicit resource grants. Unsupported operations must fail rather
than returning a fabricated application result. General live mounts and
broader network APIs require implementation and native tests; those gaps cannot be
closed merely by relabeling existing passing tests.

The socket extension is described in
[COMPACT-LINUX-SOCKETS.md](COMPACT-LINUX-SOCKETS.md); explicit file persistence is in
[COMPACT-LINUX-PERSISTENCE.md](COMPACT-LINUX-PERSISTENCE.md). Outbound resources are in
[COMPACT-LINUX-NETWORK-RESOURCES.md](COMPACT-LINUX-NETWORK-RESOURCES.md). Earlier native evidence and
limitations remain attached to their exact historical source commits.

Symbolic-link path semantics and version 2 snapshots are described in
[COMPACT-LINUX-SYMLINKS.md](COMPACT-LINUX-SYMLINKS.md).

Shared inode names and version 3 snapshots are described in
[COMPACT-LINUX-HARDLINKS.md](COMPACT-LINUX-HARDLINKS.md).
