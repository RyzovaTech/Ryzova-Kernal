# Phase 9.2: native Compact Linux subset application

This change ports the existing bounded Linux AMD64 interpreter into a native
Plan 9 user-space application named `compact-linux`. It is the first execution
adapter toward the proposed Compact environments. It does not implement general
Linux application compatibility, Windows/macOS runtimes, a binary Compact ABI,
or mounted `/compact/*/api` and `/compact/*/abi` services. Phase 9.1 negotiation
remains an independent host-side declarative contract; it does not grant access
to this executable or dispatch execution.

## Build and invocation

On an AMD64 Ryzova/9front system, install this checkout's
`ryzova/compat/linux` source at `/ryzova/compat/linux`, then run:

```
cd /ryzova/compat/linux
mk install
compact-linux /path/to/static-linux-amd64-elf
```

The native application loads at most 1 MiB of input, interprets within a 2 MiB
arena, and stops at 2048 instructions. It never jumps into ELF bytes. Supported
instructions are the existing tiny Phase 5 subset, with Linux `write`, `exit`
and `exit_group` syscalls. Only stdout/stderr writes are forwarded. Arbitrary
files, network operations, dynamic linking, GUI, threads and fork are absent.
The virtual `/compat/linux` resolver is retained for Phase 5 regression; it is
not a mounted native namespace and is not accessible from this execution subset.
A nonzero Linux exit status produces a nonempty Plan 9 exit status.

## Evidence and acceptance

The existing Phase 3 native workflow now transfers these sources, builds them
using the guest's real toolchain, installs the executable, and runs it after
rebooting the freshly source-built kernel. The strict new acceptance report is
`artifacts/phase3/phase9-compact-native.json`. Native proof is pending until this
workflow passes for the reviewed commit.

The input is a real static Linux ELF with a source-commit-specific output
challenge; its bytes also run on Linux AMD64 in reference tests. Guest SHA256,
output, exit status, syscall/instruction counts, unsupported instruction and
syscall rejection, loop budget, and nonzero guest exit are checked. Command
echoes alone cannot satisfy the evidence parser. Existing AMD64 source-build,
security, guest mTLS and regression gates remain mandatory. No physical machine
qualification is inferred from QEMU results.

Next stages: review the native proof, expand one useful Linux workload with
resource authorization, connect a resource service through native namespaces,
then independently develop Windows and macOS adapters. Each runtime runs as
software on Flex; broad application support needs its platform semantics.
