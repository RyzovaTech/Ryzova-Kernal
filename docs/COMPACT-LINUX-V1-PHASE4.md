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

## 4D seek/read over declared larger executable-resource file buffers

The finite per-file image admission cap was raised to a **measured 32 MiB**
because the frozen CPython ELF is 27,726,864 bytes. A separate legacy
4-MiB hard-coded `lseek` limit for explicitly granted executable/library
read-only fds prevented seeking into newly admitted files. The original
syscall implementation now uses the common `RYZ_PROCESS_IMAGE_MAX` for
`RYZ_NS_EXEC` descriptors; normal bounded 64-KiB file-descriptor
limits and independent 48-MiB aggregate image buffer limits remain.
A real Ryzova C guest opens a 6-MiB explicit read-only image and seeks
to byte 5,242,880; seeking beyond 32 MiB must return Linux EINVAL,
without affecting another host resource. This **does not** imply general
large-file VFS support or full ELF/stdlib compatibility.

## 4E CPython's first measured PUNPCKLDQ gap

The first target failure after the earlier SSE2/getrusage work was the
CPython 3.12.10 candidate `66 0F 62 C2` (legacy SSE2 PUNPCKLDQ). The
original Ryzova interpreter now implements the exact 128-bit low-dword
interleave for register and aligned memory sources, including self-aliasing
without corrupting source bytes. Unaligned memory and malformed forms remain
fail-closed. Executing identical, independently assembled AMD64 ELF fixtures
under host Linux and Ryzova checks results and fault behavior byte for byte.
**This does not close AMD64-ABI or APP-PYTHON** until the pinned CPython ELF
and its required stdlib/thread/subprocess/TLS workflows actually pass.

## 4E.1 CPython's next measured SIMD gap: PSHUFD

The successive frozen CPython guest test advanced past PUNPCKLDQ and failed
at the source-digest-attributed candidate `66 0F 70 E8 E5`. The bounded
interpreter now implements legacy SSE2 PSHUFD for register and aligned
memory operands, using all four immediate 2-bit dword selectors. Host Linux
vs Ryzova ELF differential tests cover register, aligned memory, self alias,
and misaligned fault rejection. The candidate RIP alone is not proof of
complete CPython execution; no APP-PYTHON or AMD64-ABI gate is closed.

## 4E.2 Distinguishing successful Python version from failed Python code

At source head `84026da...` all seven `--version`/startup guest smokes
passed, but the independent pinned CPython 3.12.10 `-c 'print(...)'`
probe failed with guest VM status 3, last RIP `0x58af90`, no denied syscall.
The source-hash-bounded ISA discovery now reports a separate
`python-code` candidate under the measured Python ELF. It **does not**
convert version-only success into APP-PYTHON completion or guess an opcode
from the RIP alone. The first actual executable-byte evidence is required
before an original instruction implementation is selected.

## 4F measured Python code-execution conversion increment

An independent source-built CPython 3.12.10 `python -c` probe advances
past version startup but stops with host-reported candidate bytes
`F3 48 0F 2A C1` at RIP `0x58af90`, the legacy SSE scalar signed
64-bit integer to binary32 conversion `CVTSI2SS`. The Ryzova interpreter
implements signed 32/64-bit variants in deterministic integer arithmetic,
**nearest ties-to-even** rounding to a 24-bit binary significand,
including negative values, INT64_MIN and precision-boundary ties. XMM
high 96 bits and EFLAGS remain untouched. A host-Linux-vs-original
interpreter ELF differential test checks exact bytes and misaligned r/m32
fetch; unimplemented scalar-double instruction remains denied. MXCSR
nondefault rounding and floating exception flags are NOT implemented or
claimed. All frozen Python stdlib, process/thread and TLS acceptance
criteria remain pending independent actual guest evidence.

## 4E default-rounding DIVSS scalar binary32 research

The measured frozen CPython `-c` reached opcode `F3 0F 5E`
(DIVSS). The bounded Ryzova interpreter now uses an integer-only
binary32 division routine for default round-to-nearest/ties-to-even,
with signed zero, normal/subnormal rounding, overflow, zero divisors
and quiet-NaN handling. It accepts register and unaligned scalar m32
sources and preserves the upper 96 bits of the destination XMM and EFLAGS.
A differential AMD64 ELF checks eight exact output vectors against both
native Linux and the Ryzova VM. The F2 DIVSD form remains unsupported.
MXCSR nondefault rounding, precise FP exceptions/signalling NaN effects,
IEEE status flags and the full CPython workflow are **not** qualified;
guest code acceptance requires a new actual target-profile result.

## 4E — Actual CPython `-c` blocker and COMISS/UCOMISS comparison subset

The checksum-locked CPython 3.12.10 target passes the 7/7 startup smokes,
but its *real* `-c 'print("CLX_PYTHON_CODE_OK")'` guest execution probe
still fails. The prior exact pinned image's `last_rip_hex=58afa7` maps to
the candidate `0F 2F 05 ...`, an AMD64 COMISS XMM/m32 scalar
comparison. That location is a **candidate**, not proof of the faulting
instruction or full Python interpreter functionality.

An original Ryzova COMISS (`0F 2F /r`) and UCOMISS (`0F 2E /r`)
binary32 EFLAGS implementation now compares IEEE-754 encoded values without
host floating point. It handles +0/-0 equality, signed finite values,
infinities, subnormals and NaNs; it writes ZF/PF/CF and clears OF/SF/AF
without modifying XMM registers. It deliberately does **not** implement
MXCSR exception flags, unmasked invalid-operation traps, COMISD scalar
double, nondefault rounding or full SSE/IEEE compliance.

One original static AMD64 assembly ELF is run on native Linux and through
Ryzova's bounded interpreter and compared byte-for-byte across ten
representative cases. Negative cases enforce unsupported prefixed COMISD
and invalid guest pointers. All source-built QEMU/driver/security and
frozen-application tests remain independent. CPython full stdlib,
multi-module execution, threads, processes, TLS and `CLX-04` acceptance
remain pending until actual complete end-to-end results are recorded.

## 4F — Next pinned CPython `-c` barrier: CVTSI2SD, MOVSD

After the COMISS increment, the next full source-pinned CPython
`-c` probe advanced from **242,806** to **245,912** guest
instruction steps but still failed with VM status 3 at RIP
`58ac9d`. The SHA-verified main executable's candidate bytes begin
`F2 48 0F 2A`, the signed quadword-to-double `CVTSI2SD` instruction.
This is a candidate association; it does not alone prove why Python stops.

The interpreter now supports `F2 [REX.W] 0F 2A` for
signed r/m32 and r/m64 with pure-integer IEEE-754 binary64 encoding
and default round-to-nearest ties-to-even. Upper 64 XMM bits and
EFLAGS are preserved. `F2 0F 10/11` MOVSD now copies exactly 64
bits and distinguishes memory-load zeroing of the upper half from
register-to-register preservation; memory stores cannot overwrite
the adjacent eight bytes.

A single static AMD64 assembly ELF verifies both host Linux and the
Ryzova interpreter byte-for-byte using extreme signed integers,
2^53 tie-breaking, negative conversions, register/memory operand
paths and memory-write boundaries. Unmapped guest memory access
must fail closed. Nondefault MXCSR rounding and sticky FP exception
semantics remain **unimplemented**, not silently declared correct.

**Do not close APP-PYTHON, AMD64-ABI or overall Linux V1 gates** on
this bounded subset. Only a fresh real CPython `-c` run and complete
stdlib, filesystem, threads/processes and TLS application workflows
can supply further acceptance evidence.

## 4G — Next pinned CPython dynamic-code blocker: scalar binary64 add/div

Pinned CPython 3.12.10 `--version` passed, but the latest real
`-c` probe failed after **245,914** executed guest steps,
with the main-ELF candidate RIP `58acaa` showing bytes starting
`F2 0F 58 C0 F2 0F 5E...`. These correspond to candidate
`ADDSD xmm0,xmm0` and `DIVSD xmm0,m64` instructions. RIP is
an initial-byte candidate, not proof of actual root cause.

Original C interpreter now implements `F2 0F 58` ADDSD and
`F2 0F 5E` DIVSD scalar binary64 values, preserving the high XMM
quadword and EFLAGS. Integer-only normal/subnormal encoding, exponent
alignment, sticky-bit arithmetic, 53-bit mantissa rounding with
round-to-nearest/ties-even, signed-zero and infinity handling are
differential-tested against a native Linux ELF for a finite set of
real values. No host floating point is used inside interpreter math.
Unmapped guest memory and malformed instructions continue to reject.

**Unqualified:** complete MXCSR sticky/status/traps, DAZ/FTZ modes,
nondefault rounding, exact signalling-NaN exception semantics,
floating multiply/subtract or all AMD64 instructions; complete Python
stdlib, threads, processes, networking and TLS remain separate.
No application or release gates are marked passed by this step.

## 4H — Pinned Python -c next blocker: COMISD / CVTTSD2SI

At exact head `7de5f0586df3f3f2bb99b7e23fdc88003a96f633`, the source-built
CPython 3.12.10 `-c` probe still fails with `status=3`, after 245929
interpreter steps, candidate RIP `58acb6`; bounded ELF bytes start
`66 0F 2F C1 ... F2 48 0F 2C C0`. These are candidate
COMISD and CVTTSD2SI opcodes. RIP alone does not prove fault causality.

The native-independent interpreter now models `66 0F 2F` COMISD and
`66 0F 2E` UCOMISD using raw IEEE-754 binary64 comparisons, correct
signed-zero/infinity/NaN ordered EFLAGS and no host floating point;
`F2 [REX.W] 0F 2C` CVTTSD2SI truncates the source binary64 toward
zero into a 32- or 64-bit GPR. NaNs and signed overflow return the
documented x86 integer-indefinite sentinel, including 32-bit GPR
zero extension. A single source-built AMD64 ELF tests normal values,
signed extremes, overflow, infinities, NaNs, register/memory operands
and fault denial, identical on host Linux and the guest VM.

Still **not** provided: architectural MXCSR sticky flags/unmasked traps,
unrestricted IEEE-754 compliance, complete CPython runtime, stdlib,
TLS, platform ABI and production kernel application execution.
Completion gates stay open until end-to-end evidence exists.

## 4I — Next frozen CPython `-c` candidate: SSE2 PADDQ

At exact PR head `5d645f8f91e226b435ecbf069dda7d67d7bd6f5d`,
the checksum-pinned CPython 3.12.10 `-c` probe executed **620,127**
guest instructions (previously 245,929) and still failed status 3
at RIP `4bd946`. Candidate initial main-ELF bytes were
`66 0F D4 C1 41 0F 11 84 24...`; first instruction is
SSE2 PADDQ xmm,xmm/m128. RIP is a candidate and is *not* itself
proof of the faulting instruction.

The interpreter now implements only `66 0F D4 /r` packed
quadword addition: 64-bit modular addition independently in
two lanes, preserved EFLAGS, register alias-safe reads and
bounded aligned 16-byte guest memory operands. Unprefixed MMX
`0F D4` is not supported. One identical source-built static
AMD64 ELF is executed on real Linux and in the bounded
Ryzova VM; it compares exact byte output, independent carry
wrap and preserved carry flags. Deliberately unaligned m128
must fault on real Linux and fail closed in the VM.

This is **not** full SSE2, native CPython stdlib workflow,
MXCSR or production CPU/ABI qualification. APP-PYTHON,
AMD64-ABI and other acceptance requirements stay open.

## 4J — Source-locked CPython code-probe budget

On exact head `43c3a13804d01bc2289cfce35e49f087fcf70f3f`,
CPython 3.12.10 `-c 'print("CLX_PYTHON_CODE_OK")'`
stopped at **status=4** after precisely **1,048,576**
guest instructions: the arbitrary diagnostic step ceiling, not a
verified unsupported instruction or successful application run.

The *specific* CPython code-execution diagnostic now requests
**8,388,608** instructions, below the audited hard maximum
**16,777,216**, and at most **120 seconds** wall-clock. Startup
smokes still use 1,048,576 steps. The logged evidence includes
which step budget was used, elapsed seconds, timeout status and
actual guest results. Timeouts fail closed with runner exit 124 and
`passed=false`. This does not relax production defaults,
native guest RAM, file, network or aggregate instruction controls.

An extended **test-only probe** does not close RESOURCE or APP-PYTHON
requirements. Unmodified full Python application, stdlib,
threads, subprocesses, TLS, native QEMU, installation and
recovery acceptance remain independently required.

## 4K — CPython code-probe PCMPEQD diagnostic increment

The seven frozen target version smokes already pass. Their result is not
APP-PYTHON qualification: the source-locked CPython code-execution probe
still reports Ryzova status 3 and `66 0F 76`, the SSE2 PCMPEQD packed
doubleword comparison. Original Ryzova CPU code now handles only the
`66 0F 76 /r` XMM/XMM or aligned m128 variant, comparing 4 independent
little-endian dword lanes and returning all-one or all-zero results. It
preserves EFLAGS, supports XMM8+ and register self-alias, rejects unaligned
legacy SSE2 loads and does not claim the unprefixed MMX variant.

`test_phase9_pcmpeqd_differential.py` builds and executes the *same* static
x86_64 ELF on host Linux and original Ryzova guest CPU interpreter, comparing
all 72 bytes of results and carry-flag preservation, with independent
negative misalignment/MMX tests. That micro-test, even after CI success,
does not complete `AMD64-ABI` or `APP-PYTHON`; those gates require the
pinned CPython code/stdlib and full application workflows under bounded
resource budgets and native guest qualification.

## 4L — Exact main-ELF mapped high-water vs relocated musl ISA diagnosis

The pinned CPython 3.12.10 code-execution probe reached 6,458,959 VM
steps and failed closed at `RIP=a4292e` (VM status 3). The prior
diagnostic reported no candidate because it assumed musl's loader bias
was always `0x800000`, despite `process.c` relocating the loader
above large PIE main PT_LOAD mapped spans on a 2-MiB boundary.

The read-only ISA discovery now reproduces the source-built kernel's
page-rounded *mapped memory* high-water rule, not file length, and
pins the loader bytes to the measured musl SHA-256. It attributes
candidate bytes in the initial musl interpreter both for version
smokes and the independent CPython `-c` probe. Invalid ELF mappings,
unproven loader provenance, page padding, and unknown instruction
addresses return **no candidate**. Tests cover relocated vs stale
fixed-loader RIP, mismatched musl digest and malformed ELF.

No unqualified opcode was enabled, no guest instruction or runtime
budget was increased, and no process/memory or application acceptance
gate was marked passed. A candidate RIP remains only a *candidate*,
not verification of the failing opcode.

## 4M — Native musl loader STMXCSR candidate and default-only MXCSR

On the last independently measured frozen CPython `-c` probe,
`RIP=a4292e` mapped to pinned musl 1.2.6 bytes
`0F AE 1C 24 58 C1 E8 03 25 00 0C 00 00 C3 31`, beginning with
`STMXCSR m32`. RIP is a candidate, not proof of an instruction defect.
A source-built host Linux reference ELF independently validated
`STMXCSR`, default `LDMXCSR 0x1f80`, stack memory and EFLAGS-preserving
behavior.

The finite Ryzova interpreter now models `0F AE /3` m32 stores and
`0F AE /2` m32 loads **only if MXCSR remains exactly 0x1f80**.
Other values fail closed (VM opcode unsupported) rather than silently
running incorrect floating-point controls. Register-only forms and
unmapped m32 are independently rejected; reserved/unmodeled 0F AE groups
remain unsupported. `test_phase9_mxcsr_differential.py` executes the
same static x86_64 ELF on Linux and the Ryzova interpreter and compares
all 20 result bytes and invalid-operand behavior.

This is **not full MXCSR support**. MXCSR sticky exception status,
unmasked traps, DAZ/FTZ, altered rounding and multi-thread FP state
qualification remain open. Native CPython full code/stdlib and
AMD64-ABI acceptance require the subsequent frozen guest result and
native QEMU evidence before any completion claim.

## 4N — Step-limit classification after musl STMXCSR fix

At PR #81 commit `5524ee2`, the pinned CPython `-c` probe progressed
from `vm_status=3` (unsupported `0F AE /3 STMXCSR` candidate in pinned
musl) to **`vm_status=4`**, exactly **8,388,608 guest instructions**.
The current RIP `4bddf4` maps to main-ELF bytes beginning
`48 8B 94 C5 78 0F 00 00`; this is **not** a demonstrated unsupported
opcode or application success. The failure is the declared step budget.

For a new *diagnostic only*, increase CPython's `-c` probe from 8,388,608
to **16,777,216 instructions**, exactly the already audited
`jobs_probe -b` hard maximum. No kernel/runtime maximum, production
default, file size, host RAM, resource grant or native guest security
ceiling is increased. Both 120-second wall timeout and explicit
failed-probe records remain in place. Unit tests assert the new finite
budget, reject values above it and prevent arbitrary other frozen
targets using this enlarged diagnostic profile.

A successful short `-c` print still cannot qualify full Python stdlib
or resource budgets. If 16,777,216 steps expire, it is a **STEP_LIMIT**
result and must NOT be misrepresented as an opcode failure or PASS.

## 4O — Status-specific, fail-closed RIP candidate attribution

A sampled RIP at `vm_status=4` (instruction budget exhausted),
`vm_status=5` (unsupported syscall) or `vm_status=2`
(memory/map fault) is **not evidence of an unsupported opcode**.
Read-only CLX-04 diagnostics now attribute pinned ELF/musl instruction
candidate bytes **only for vm_status=3**, the interpreter's explicit
`RYZ_VM_OPCODE_UNSUPPORTED` result. Console evidence carries a
`failure_kind` label and suppresses any manually supplied candidate
if the actual status is not an unsupported opcode. Unit tests cover
real SHA-bound Python and BusyBox failure rows, including 16-MiB
instruction-step exhaustion vs supported instruction bytes.

No CPU instruction or resource cap is changed by this improvement;
it prevents false forensic conclusions and does not close any
of the 17 mandatory Linux V1 acceptance gates.

## 4P — Locked CPython 16M-step probe MOVHLPS candidate

On exact head `50db500d`, the pinned CPython `-c` guest probe
progressed past prior musl STMXCSR and the former 8,388,608-step
limit. At its bounded 16,777,216-step hard ceiling it instead
recorded **VM status=3** and `RIP=506485` with main-ELF candidate
bytes beginning `0F 12 D0` (legacy SSE MOVHLPS register form).
The sampled RIP is only a candidate until differentiated execution.

Original interpreter code now handles unprefixed `0F 12` with
MOVHLPS register-low/high source semantics and MOVLPS m64
unaligned memory loads, and unprefixed `0F 13` with MOVLPS m64
stores. The ModRM register encoding of `0F 13` is rejected;
faulting guest memory is rejected and EFLAGS is preserved. It does
not claim MOVLPD, AVX, aligned-only restrictions or unrelated SSE
instructions. A **single identical source-built static ELF** verifies
byte-for-byte host Linux versus Ryzova output, self-aliasing,
XMM8 with REX, unaligned memory and invalid operands.

The separate read-only diagnostic staged in the same PR rejects
claiming opcode candidates on step limit, syscall or mapping errors.
These incremental tests do **not** close `AMD64-ABI`, `APP-PYTHON`,
or any other V1 gate; the next source-pinned Python code/stdlib,
native kernel and resource workflows must be independently verified.

## 4Q — Source-locked CPython MINSD scalar comparison candidate

At the exact prior PR #81 head `6dd0406d`, the pinned CPython 3.12.10
`-c` diagnostic progressed to **9,140,806** guest interpreter instructions
and returned `VM status=3` at `RIP=62a24d`. Digest-bound initial main ELF
bytes began `F2 0F 5D CA` (SSE2 scalar MINSD). Sampled RIP is only a
candidate and does not independently prove the faulting opcode.

The original bounded interpreter adds **only F2 0F 5D /r** MINSD
with register or unaligned m64 second operand. It compares raw IEEE-754
binary64 fields without a host floating-point unit, selects the second
operand for equal values (including +0/-0) and unordered comparisons
(including NaN), retains exact NaN bits, preserves the high 64 bits of
XMM and EFLAGS, and reads only the 8 guest memory bytes. A single
source-built static AMD64 ELF compares 152 exact output bytes against
native Linux across ordered values, signed zero, qNaN, register alias,
REX XMM8 and unaligned memory; separate unmapped memory and unsupported
MINSS/MINPD variants fail closed.

MXCSR exception sticky flags, non-default rounding/DAZ/FTZ, unmasked
traps, complete SSE/AMD64 ABI and Python stdlib remain **unqualified**.
No acceptance gate or budget is changed based on this isolated test.

## 4R — Pinned CPython SSE2 ANDPD candidate and strict differential

At exact head `da843592`, source-locked CPython 3.12.10's independently
executed `-c` probe reached **9,140,361 guest instructions** before
`VM status=3`, with SHA-locked main ELF sample at `RIP=62a25d`,
bytes `66 0F 54 CA` (legacy SSE2 ANDPD). The sample is a diagnostic
candidate, not proof of an instruction failure.

The original AMD64 interpreter adds only `66 0F 54 /r` ANDPD,
computing an exact 128-bit bitwise AND of destination and source XMM
registers or aligned guest m128. Aliasing/REX XMM8, all 16 bytes,
unaltered EFLAGS and checked guest memory bounds are covered.
Legacy memory operands reject non-16-byte alignment. The unprefixed
ANDPS form is **not** silently treated as ANDPD.

The new host/guest differential static ELF compares **88 output bytes**
including exact 128-bit lane bit patterns and carry-flag preservation.
Independent negative tests cover host SIGSEGV vs guest denied
unaligned m128, and an explicitly unsupported unprefixed opcode.
This is not full AMD64/SSE2 ABI, pinned CPython stdlib execution,
application resource qualification or a V1 acceptance gate completion.

## 4S — Locked CPython ANDNPD complement-destination candidate

On original-source head `6a22212`, the pinned CPython 3.12.10
`-c` interpreter reached **9,145,526 guest instructions** and failed
closed with `status=3` at `RIP=62a2a1`, candidate bytes
`66 0F 55 D0` in the SHA-locked executable (SSE2 ANDNPD).
This is only source-attributed sampled RIP, not a claim of successful
CPython or a complete ISA root cause.

The original bounded CPU interpreter now models **66 0F 55 /r**
ANDNPD as `(~DEST) & SRC` over 128 bits, including register aliases
and XMM8+, a 16-byte-aligned guest m128 source, unchanged flags and
no host FP state. Self-alias returns zero, unlike ordinary ANDPD.
Misaligned/missing m128 fails closed; unprefixed ANDNPS is not claimed.
The same static AMD64 ELF is executed on Linux and Ryzova, comparing
all **88 output bytes** plus separate native/guest failure cases.

No ELF/resource/step budgets were increased. Nondefault MXCSR,
full AMD64 ABI, Python stdlib workloads and native application V1
acceptance remain open and require independent fresh-head evidence.

## 4T — Native Linux scalar CMPSD predicate qualification

At prior exact head `80496582`, pinned CPython 3.12.10's original
`-c` guest probe reached **9,144,214 instructions** and returned
`VM status 3`, `RIP=62a2ae`, SHA-attributed main ELF bytes
`F2 0F C2 D8 06`, a **scalar-double CMPSD imm8=6** comparison.
The sampled instruction is a *candidate* and does not by itself prove
an ABI root cause.

The bounded interpreter adds only legacy `F2 0F C2 /r ib` for eight
SSE2 scalar-double predicates 0..7: EQ/LT/LE/UNORD/NEQ/NLT/NLE/ORD.
It compares raw IEEE-754 binary64 representations, preserving the
high XMM 64 bits and EFLAGS and writing low all-ones or all-zero
masks. Unaligned m64 loads, XMM8+, register aliases, NaN and signed
zero comparisons are differential-tested. Immediate/displacement
order accounts for RIP-relative addressing. Non-F2 variants and
reserved immediate high bits fail closed instead of being guessed.

One source-built static ELF is run on native Linux and the Ryzova
interpreter with exact **232-byte** output, plus unmapped memory and
unsupported-variant negative tests. qNaN exception status, unmasked
MXCSR traps, DAZ/FTZ and nondefault rounding remain unmodeled.
This does NOT close `AMD64-ABI`, CPython stdlib workflow,
`RESOURCE`, `MEM-PROC` or any Linux V1 acceptance gate.
