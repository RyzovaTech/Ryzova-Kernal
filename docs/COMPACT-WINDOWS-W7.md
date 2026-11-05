# Compact Windows W7 — ARM64 and post-W6 qualification engineering

This is the **next research branch**, not a retroactive general Windows
compatibility qualification of the W1–W6 AMD64 subset on `main`.

## W7A: Actual original ARM64 PE32+ execution

Files:
- `ryzova/compat/windows/arm64_probe.c` and `arm64_probe.h`
- `ryzova/compat/windows/arm64_probe_main.c`
- `tests/fixtures/windows_w7_arm64_reference.c`
- `tests/test_compact_windows_w7_arm64.py`

The tests independently compile an unmodified C source to genuine Windows ARM64
PE32+ machine code with `clang --target=aarch64-windows-msvc` and
`lld-link /machine:arm64`. The **-O0 and -O2 binaries differ in real
instructions**; Ryzova's new bounded C interpreter executes them on the
Ubuntu CI host and must return the same integer 37.

The loader checks PE32+, ARM64 classic machine 0xAA64, console subsystem,
directory counts and section/file ranges, exact aligned executable entry,
overlap, W+X, file-size and memory budgets. The finite ARM64 decoder admits
a small subset of MOVZ, MOVK, ADD/SUB immediate, LDR/STR W/X, B/BL,
NOP, RET and stack accesses; all other opcodes and SVC are blocked. An
instruction budget stops loops. The code neither runs a kernel nor
forwards syscalls or resolves host DLLs.

ARM64EC (0xA641), ARM64X (0xA64E), AMD64 (0x8664), unknown machines,
relocations, imports, TLS and dynamic loaded modules are **explicitly
unsupported**, not silently interpreted as ARM64 classic.

### Precise boundary

A real ARM64 compiler-generated instruction executed inside a bounded
interpreter on an AMD64 CI host is valuable ISA/PE proof. It is **not**:
native Ryzova ARM64 boot, validated ARM64 Windows ABI (x18/TEB, FP/SIMD,
exceptions/unwind), run of actual Windows ARM64 user applications, general
Win32 imports, ARM64 device drivers or physical ARM64 hardware support.

Next milestones for a genuine ARM64 Windows runtime: Windows ARM64 stack
and register ABI conformance, PE relocations/import tables under declared
capabilities, exception/unwind and TEB validation, Windows-host reference
differential, named actual ARM64 console workloads, source-built ARM64
Ryzova QEMU guest with independent receipt, and finally physical board
qualification with device IDs and firmware inventory. Every milestone
requires independent tests and a distinct acceptance decision.

## W7.3: Linux AArch64 userspace — independent real-PE ISA differential

A dedicated W7 CI job now cross-compiles the original bounded Windows ARM64
PE interpreter into **Linux AArch64 ELF64** with the GNU AArch64 compiler.
The ELF machine must be 183 (EM_AARCH64) and the program runs with
`qemu-aarch64` on an AMD64 Linux runner. The same unmodified interpreter
sources also compile into an independent Linux AMD64 host executable.

Both binaries execute **the same real Clang/LLD Windows ARM64 PE32+**
files at O0/O2 from the existing integer and non-inlined call fixtures.
Exact exit status 37, executed instruction counts, final instruction
and last RVA must match across both interpreter ISAs. The source SHA-256,
both interpreter ELF SHA-256 and all Windows PE SHA-256 values are retained.

Five real-PE mutations are required to fail identically on both targets:
ARM64EC machine mismatch, SVC syscall, illegal opcode, 4096-step infinite
loop, and unapproved import directory. These are fail-closed portability
and bounded ISA tests, not a claim of Windows API or syscall coverage.

**This is QEMU userspace emulation, NOT a source-built Ryzova ARM64 kernel**.
No ARM64 kernel is booted by this job, no actual Windows ARM64 host
reference runs, and no physical ARM64 board is tested. All corresponding
release and hardware acceptance fields remain false. The stronger
next requirement is a source-built ARM64 **Ryzova QEMU-system guest**
running a source-identical Windows ARM64 PE with independent guest serial
and resource-permission evidence.
## W7.4: Genuine Windows ARM64 host and exact PE comparison

GitHub Actions provides a real Windows 11 ARM64 runner (Visual Studio 2026
image). The W7 native-host job runs on this actual Windows ARM64 OS,
compiles the four import-free original Windows ARM64 C source fixtures
with Clang/LLD (integer and function-call cases at O0/O2), and **executes
all four PE32+ executables as Windows ARM64 processes**. Expected results
are exit code 37, zero stdout/stderr, exact 0xAA64 machine type, console
subsystem, and no DLL import table. The original source SHA-256, PE
SHA-256, OS image version and 4/4 execution receipts are archived together
with only the original source-built PE files, not Microsoft system binaries.

A second Linux job downloads these **exact same PE bytes** from Windows
ARM64 (no independent PE recompile for the comparison), verifies each
host-source, guest-PE and exit receipt against the checked-out exact PR
head, and runs the PE in two independent builds of the finite interpreter:
Linux AMD64 and Linux AArch64 under QEMU userspace. Both must match the
actual Windows ARM64 native-host exit result 37, and must agree on the
interpreter step/RVA/opcode receipts. Five negative mutations of a
Windows-host-supplied binary must fail closed in both interpreter ISAs.

**Important acceptance boundary:** Windows ARM64 *host* reference and
QEMU *userspace* cross-ISA agreement establish original Windows ARM64
PE compatibility for a narrowly limited import-free finite C program.
These jobs do not boot the Ryzova ARM64 kernel, validate imported Win32
APIs, demonstrate arbitrary Windows applications, or perform physical
ARM64 device/firmware qualification. All native Ryzova ARM64, Windows V1
and W9 physical hardware release flags remain false.
## W7.5: Native Ryzova ARM64 QEMU-system boot qualification — implementation under test

The new `scripts/compact_windows_w7_native_arm64_system.py` and
`.github/workflows/compact-windows-w7-native-system.yml` attempt the
**first actual source-derived Ryzova ARM64 kernel boot**. This is deliberately
different from Linux `qemu-aarch64` userspace translation and from executing
Windows ARM64 PE images on Microsoft's own ARM64 Windows host.

The runner is required to:

1. Verify the unchanged, pinned W6 9front AMD64 builder image by its
   original SHA-256, then boot it in a separate writable QEMU layer.
2. Archive and SHA-256 hash tracked original Ryzova ARM64 kernel,
   port and boot sources from the **exact PR head**; transfer the archive
   over isolated QEMU user-mode networking with independent in-guest SHA.
3. Cross-compile the original `sys/src/9/arm64/qemu` kernel inside the
   9front builder using its own `7c`/`7l` tools and create the actual
   `9qemu.u` image. A compiler-missing or build-failed result is a
   **hard failed qualification**, not a simulation or a skipped test.
4. On the frozen AMD64 builder image, ARM64 `7c`/`7l` exist but
   `/arm64/lib/libc.a` is initially absent. Cross-build all seven
   mandatory ARM64 kernel link libraries from exact tracked source.
   The native ARM64 full bootfs requires additional unbuilt
   `/arm64/bin/paqfs`, `factotum` and other userland tools. A
   **separately hashed test-only EARLY-BOOT qemu config** therefore omits
   the final `bootdir` section. The original qemu source hash is retained
   and the deterministic derived config SHA is independently verified.
5. Build the resulting *early-boot-only* kernel with forced 9front `7c/7l`
   rebuild, copy it to the builder's FAT volume and independently
   re-extract/hash the actual binary.
6. Start a separate `qemu-system-aarch64` and require the ARM64
   `Plan 9` and `cpu0: 1000MHz QEMU` serial markers. Even if this
   passes, it is **kernel early-main proof**, not a complete boot to
   functional userland, and absolutely not a Windows ARM64 PE execution.

This is a strict **experimental EARLY-BOOT** test: a pass must be
backed by actual full-system QEMU AArch64 console evidence, never mocked
serial data in Python unit tests. Earlier real attempts proved source
libraries compiled on the W6 AMD64 builder but exposed missing ARM64
bootfs executable dependencies. No native ARM64 **full** boot,
Windows guest PE, driver binding or physical board is qualified by this
test.

Even a successful native ARM64 *kernel boot* **does not execute a Windows
ARM64 PE in that kernel**. That requires a future original ARM64 Plan 9
userspace bridge/PE admission and actual guest I/O/exit receipt linked
to the very same Windows ARM64 PE32+ built on Windows ARM64 in W7.4,
then strict import/exception/TEB/capability tests. Physical ARM64 board
and W9 power-cut gates remain independent and false.

## W7B: Real hardware power cut

`scripts/compact_windows_physical_powercut.py` and
`tests/test_compact_windows_physical_powercut.py` validate evidence
*format*, integrity and external Ed25519 witness signatures. They demand
a controller/firmware/serial-hash inventory, independently witnessed power
absence, three unique ACK-to-cut-to-reboot SHA-recovery cycles, external
monotonic event counters, and two injected sticky-ACK-denial outcomes.

**No actual hardware is available to this coding environment.** Passing
synthetic manifest and signature tests does not represent any physical
test. The verifier always outputs `physical_hardware_qualified=false`,
and cannot issue release certification.

A separately configured external witness public key and out-of-band pinned
fingerprint are mandatory. Committed signing keys or self-supplied trusted
credentials are unacceptable. Independent physical test operator and
hardware release reviewer must examine the real test setup and signed data.
Only an independently verified real physical power-cut experiment can
qualify physical persistence; VM SIGKILL is not equivalent.

## W7C: General Windows application support

The merged W1–W6 profile provides **selected** AMD64 console, file and CRT
imports only. The current finite `windows-v1-plan.json` lists supported
API symbols and excludes GUI, COM, registry, .NET, DirectX, arbitrary
networking, WoW64 and kernel drivers. Broad app compatibility is **not
claimed** and cannot be concluded from two import-free ARM64 fixture
executions.

Priority for future original implementations: trusted import-boundary
inventory of named real applications; per-application declared API
coverage and negative rights tests; process, thread and exception models;
Windows UTF-16 filename/path compatibility; named compiler/toolchain
end-to-end workflows; sockets/TLS, UI/graphics and general platform
services only after independently scoped capabilities and tests. Keep
software guest/host resource boundaries strict, and separate the Windows
track from the Compact Linux work in PR #81 and the driver-agent PRs.

## Source authority

Microsoft [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
distinguishes ARM64, ARM64EC, ARM64X and AMD64 machine values.
Microsoft [ARM64 Windows ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions)
specifies x18/TEB, ARM64 register conventions and 16-byte stack alignment.
The imported QEMU/W6 storage evidence belongs to the **separate AMD64
virtual-storage profile** and is not a substitute for physical or ARM64
evidence.

W7 remains a draft until exact-head tests pass and a complete, scoped
acceptance review authorizes any merge. Do not overwrite W1–W6 acceptance
metadata or mark the seven release requirements complete.

## W7.2 bounded compiler ABI / function call probe

A second independent `aarch64-windows-msvc` source uses an explicitly
non-inlined C function and a volatile stack local; both -O0 and -O2 PE
builds are executed by the original Ryzova interpreter and must return 37.
The -O0 binary contains an actual `BL` to another function and a saved
and restored `X30` link register across 16-byte-aligned SP memory.
This validates a **finite no-import ARM64 GPR / call / stack subset** only;
Windows ARM64 TEB/x18, volatile/nonvolatile SIMD, platform exceptions,
stack probing, imports and native kernel/board execution remain unqualified.

## W8 direct + delay-load Win32 dependency inventory

The read-only PE audit now decodes standard direct PE32+ thunks and
RVA-based MSVC `ImgDelayDescr` tables (PE directory 13). Delay-load
DLL names and imports are reported **separately**; no automatic dynamic
resolver exists, so even familiar `kernel32.dll` names within a delay
import do not qualify the application as runnable. Old VA-based delay
imports, nonzero reserved descriptor/ordinal bits, bad RVAs, unterminated
thunks, and unbounded module/symbol counts fail closed. Nonempty TLS and
CLR runtime directories also prevent a false profile-covered result.
This is a **compatibility inventory**, not an implemented delay loader,
Win32 networking, GUI/registry, or application execution claim.

PE layout reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

## W8 bounded Win32 virtual process identity

The existing single-process/single-thread AMD64 compact Windows console
runtime now recognizes two **additional explicit Kernel32 import thunks**:
`GetCurrentProcessId` and `GetCurrentThreadId`. Each returns the stable
namespace-local DWORD 1 for the one permitted guest process/thread.
No physical host process/thread ID is revealed. Like all API thunks, the
launcher and PE import plan must both authorize these IDs before guest
execution. Per-machine call counters and last-error preservation have
standalone C/ctypes regression tests; the existing 28 API tokens preserve
their historical indices. The declared W1–W6 stable API subset and seven
release requirements remain unchanged, and this extension is **not** a
Windows process/thread creation/scheduler, general compatibility or
physical hardware qualification.

## W8 compiler-built PE import-inventory differential

The import auditor now includes a **real x86_64 Windows PE32+ binary**
compiled by Clang and linked with `lld-link` against a metadata-only
`KERNEL32.dll` import library. The analyzer must independently discover
`kernel32.dll!WriteFile` and match it to the W1–W6 declared profile.
This proves parsing of a genuine toolchain-generated thunk/descriptor,
**not execution**, Win32 API coverage beyond that one import, or actual
Windows guest compatibility. The dedicated audit CI requires the LLVM
linker and cannot quietly skip this test; older suites may skip the
cross-compile test if they do not install a Windows-target linker.
