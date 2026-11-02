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
