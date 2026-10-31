# CLX-04 entry and finite qualification sequence

Phase 4 is not qualified merely because Phase 3 fixture tests are green.
The entry artifact is `compact-linux-target-profiles.json` (the CI filename is
`target-profiles.json`), produced from the seven frozen source-built musl targets.
Every target must have a matching executable hash, a passing version-identical
Linux-reference smoke, an actual Flex admission result and concrete failure data.
`phase4_entry_ready=true` means those inputs exist; it does not pass RESOURCE,
AMD64-ABI, any application workflow, or Linux V1.

| Increment | Work | Required exit evidence |
| --- | --- | --- |
| 4A | Capture all named executables, dependency closure and first guest failures | Version/hash-bound build manifest and seven reference/guest records |
| 4B | Resolve actual ELF image/span and memory-profile blockers | Explicit measured caps, aggregate allocation enforcement, malformed-image and exhaustion tests |
| 4C | Implement target-required integer, floating point and baseline SSE2 operations | Linux differential cases including fault behavior, rounding and preserved machine state |
| 4D | Resolve interpreter, dynamic libraries, relocations and TLS failures | Explicit namespace grants, dependency closure, symbol/TLS tests and denied-path tests |
| 4E | Resolve startup and required module/library failures for every target | Actual guest version/startup/import runs; unsupported operations fail explicitly |
| 4F | Qualify exact source through fresh native QEMU and inherited regression/security checks | Artifact/source tree match, no required skips, every declared Phase 4 exit demonstrated |

4B–4E are driven by actual failing target runs, not speculative instruction lists.
Each discovered gap receives a focused test and a finite regression exit. A cap
is not raised to an unlimited value to make a program load; its candidate value
must come from measured demand and retain aggregate admission/failure checks.
Floating point work must preserve IEEE-754-visible behavior rather than replace
computation with fabricated outputs. Libraries remain explicit grants; live
resource fds cannot silently bypass the existing mmap/revocation contract.

The existing Phase 3 gate requires full measured guest target profiles. Loader
and ISA failures can therefore require 4B–4E work before Phase 3 can close. Keep
that dependency visible in `linux-v1-plan.json`; do not relabel reference Linux
runs as Flex guest completion. Full network/certificate and PTY workflows retain
their later phase gates. Operational ARM64 and physical hardware remain separate.

## 4A failure-location qualification helper (separate stacked PR)

A read-only host-side `scripts/compact_linux_isa_discovery.py` references
the exact frozen target ELF digests from `target-profiles.json`. The utility
tries to correlate each bounded `last_rip_hex` with bytes in an existing ELF
PT_LOAD segment, using only the Ryzova runtime's documented main-PIE bias
(`0x400000`), non-PIE bias zero, and initial musl dynamic interpreter bias
(`0x800000`). The result is archived as `target-isa-candidates.json`
alongside target build/ref/guest measurements when the report exists.

**Security and scientific limitations:** a sampled RIP may describe the
instruction after a fault, an unsupported syscall return, a stale instruction
pointer, or a page dynamically mapped by the musl loader. It is **not**
guaranteed to be the faulting opcode. Unknown/malformed/unmapped locations
produce null rather than a guessed instruction. Files must stay in the measured
root and match the recorded SHA-256; a normal in-root /bin/gcc or /bin/as
symlink is allowed but a symlink escape is denied. The helper never executes
the sampled bytes, changes user-space ISA behavior, adjusts limits or
converts a failed guest workload into an acceptance success.

Exact source-built native QEMU and tests for actual CPU semantics, loader
relocations, FP/SIMD behavior and guest application workflows remain mandatory.
The helper is a triage aid to determine which **original Ryzova-specific ISA
implementation** should be built and tested next; it does NOT close 4B–4F,
AMD64-ABI or any Compact Linux V1 application acceptance ID.

## 4B bounded image buffers and non-overlapping initial loader

The source-built CPython 3.12.10 target executable was measured at **27,726,864
bytes**; the previous fixed 4-MiB ELF file cap rejected it before interpreting
the image. The candidate upper bound is now **32 MiB per file** and **48 MiB
across main + explicit executable/library grant image buffers**. These image
buffers are **separate** from the existing maximum 16-MiB per-process address
arena and nine-arena aggregate cap. The C API and host probe both reject
oversized images and cumulative grants before allocation/dereference. A
sparse-file test admits an ELF of the actual measured CPython byte length,
while a 32-MiB+1 image and an over-48-MiB grant pair fail closed.

The measured CPython PT_LOAD footprint exceeds the old 4-to-8-MiB gap between
main PIE and the hard-coded musl interpreter. The loader now retains the
historical 0x800000 interpreter bias for small programs but chooses a
non-overlapping 2-MiB-aligned bias beyond the main's mapped high address for
larger programs. A synthetic, valid AMD64 PIE spanning 6 MiB and a separate
executable interpreter must complete a real Ryzova host VM run. Both the ELF
input limit and loader placement remain bounded by original canonical address
and 16-MiB arena admission checks.

**This is not proof that CPython starts, imports modules, or supports required
SSE2/FP instructions.** Real pinned guest CPython and full pipeline workloads
must be separately demonstrated before CLX-04 or MEM-PROC/RESOURCE may close.

## 4A exact unsupported-syscall evidence

On fail-closed guest syscall rejection, the runtime records the original
guest number and a distinct validity flag in the diagnostic result. It never
forwards unknown syscalls to Linux. The pinned host differential uses an
actual AMD64 ELF containing `mov eax,999; syscall` and must report Ryzova
status 5 plus unsupported syscall 999. The frozen-target profile includes
this number only when the validity flag is set. Failed guest execution
remains failed; no compatibility gates are closed by emitting diagnostics.

## 4C observed AMD64 SIMD compatibility increment

Source-pinned guest diagnostics identified no-prefix `0F 16 /r` MOVHPS /
MOVLHPS, legacy SSE2 `66 0F 73 /3,/7` PSRLDQ/PSLLDQ and
`66 0F EB /r` POR as the first target-required instruction set gaps.
Original Ryzova interpreter cases implement byte-accurate operations and
retain preserved XMM halves and unaffected EFLAGS. Aligned POR memory
operands are required; Linux faults on misaligned m128 and the VM returns
a bounded map error rather than silently permitting it. Source-built
AMD64 Linux-vs-Ryzova differential fixtures and negative-encoding tests
provide evidence on the exact PR head. This does not imply complete SSE2,
x87, IEEE-754, TLS or general AMD64 compatibility. Full pinned CPython,
GCC and Make workflows remain required for the Phase 4 exit.

## 4D bounded getrusage RUSAGE_SELF compatibility

The pinned Binutils host-reference guest failure identified Linux AMD64
syscall 98 (`getrusage`). The initial original Ryzova scope implements
`RUSAGE_SELF=0` only with the full 144-byte x86_64 struct; it validates
the guest's writable address range before modifying memory and returns
guest `EFAULT` and `EINVAL` for invalid address/who. It records virtual
user time from retired guest instruction steps at 1 logical nanosecond per
step. Unmeasured resident set and other counters are **zero, not
physical measurements**. The host OS is not queried, and the result
must never be described as actual CPU/RAM resource consumption.
Other `who` categories remain unimplemented and reject explicitly;
`RUSAGE_CHILDREN`, `RUSAGE_THREAD` and full Linux rusage semantics
remain outside this bounded increment.

A source-built AMD64 Linux ELF verifies successful `RUSAGE_SELF`,
invalid-who and invalid-pointer results on both host Linux and
the original Ryzova guest interpreter, without comparing their
inherently different time/RSS values. This does not qualify the
full Binutils assembler workflow or CLX-03 RESOURCE budgets.
