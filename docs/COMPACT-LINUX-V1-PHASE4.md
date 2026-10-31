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
