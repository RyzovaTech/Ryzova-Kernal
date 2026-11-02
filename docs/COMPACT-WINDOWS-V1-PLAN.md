# compact/windows: bounded AMD64 console profile

W1 freezes a Windows-specific request contract and reproducible metadata audit.
There is no Windows application execution in Flex yet. The contract validator is
an offline Python shape checker, not a launcher, capability issuer or export table.
The shared compact negotiation remains unchanged. This work does not change Linux.

## Finite phases

| Phase | Deliverable | Completion evidence |
| --- | --- | --- |
| W1 | ABI/resource request contract, baseline audit, reference source | 14 Windows contract/audit tests, 10 existing PE tests, Windows-host compile/run receipt |
| W2 | PE32+ AMD64 loader, bounded memory, entry and execution ABI | Actual import-free PE executes and returns a full DWORD in Flex; malformed images denied before allocation/execution |
| W3 | Declared kernel32 console/memory imports | Compiler-built fixture writes exact bytes and exits; argument/environment/memory/error fixtures pass |
| W4 | Namespace-backed files and typed handles | Rights, traversal, handle lifetime, cross-environment denial and file I/O fixtures pass |
| W5 | Named compiler/CRT workloads and runtime error behavior | Freeze the exact additional imports/instructions first; each selected workload passes; unsupported features fail explicitly |
| W6 | Resource enforcement and native Flex qualification | Source-identified QEMU receipts, boundary measurements and regression CI pass |

W1 completion does not require W2-W6 runtime evidence. All runtime requirements
in `ryzova/compact/windows-v1-plan.json` remain pending. Completion means this
named profile only, never general Windows compatibility. New APIs, architectures
or workload classes require an explicit profile revision and evidence.

## ABI and interfaces

The first profile is `windows-amd64-pe32plus-v1` / `console-win32-v1`.
Use Windows LLP64: DWORD and long are 32 bits, pointers are 64 bits. Win64 calls
use RCX/RDX/R8/R9, 32-byte shadow space, prescribed 16-byte stack alignment,
nonvolatile GPRs and XMM6-XMM15, and no SysV red zone. Preserve the entire 32-bit
process exit code. Per-thread last-error state is separate from process exit.
W2 must specify bootstrap state and TEB/PEB requirements before accepting programs
that depend on them. Never execute direct NT syscalls on the host.

The planned import list is machine-readable in the plan and validator. DLL names
are case-insensitive; export names are case-sensitive. Only explicit imports may
resolve to Flex-owned API thunks. No host DLL search, ordinal fallback, arbitrary
host forwarding or privileged namespace bind. W1 implements none of these thunks.

Example request (validation attaches no authority):

```json
{
  "schema": "compact-windows-request/v1",
  "environment": "compact/windows",
  "api_major": 1,
  "api_minor": 0,
  "abi": "windows-amd64-pe32plus-v1",
  "profile": "console-win32-v1",
  "apis": ["kernel32.dll!WriteFile"],
  "resources": [{"ref": "stdout", "kind": "console", "rights": ["write"]}],
  "limits": {}
}
```

Resources are opaque requested references, not filesystem paths or capabilities.
A future trusted Flex launcher must attach authorized resources to the caller's
namespace. Directory rights are read/write/create/list/metadata; console rights
are write only. W4 must define guest drive/path mapping, UTF-16 handling,
case behavior, object identity, link/traversal policy and close semantics before
file qualification. Network resources need a future declared profile; no implicit
network authority is included here.

Candidate ceilings: PE file 4 MiB, mapped image 64 MiB, aggregate image buffers
16 MiB, guest memory 64 MiB, stack 64 KiB, 32 handles, 32 imports, 4 modules,
one thread/process, 262144 instructions, 64 KiB per I/O and per file.
They bound manifest requests only today. W2-W6 must measure and enforce allocation
before use, including aggregate buffers and mapped/stack memory accounting.
A sparse mapped image can exceed its on-disk buffer size. Increasing limits is
not evidence of workload support.

## Current PE audit and ownership boundary

Baseline main: `a1802327bf8790e03fd6d04c45196b910a53f3d1`.
`ryz_pe64_plan` validates metadata, including AMD64/PE32+, section bounds,
entry backing, byte overlap and W+X denial. It rejects DLLs and selected import,
exception, relocation, TLS and CLR directories. It neither maps nor executes PE.
The probe imposes a 4 MiB input cap; callers of the C planner need their own cap.

The committed audit pins source and fixture SHA256 values and reproduces six
accepted metadata variants: GUI subsystem, unaligned/noncanonical image base,
zero header size, raw section/header alias and delay-import directory.
Some fields are outside the old planner's purpose; these are W2 admission
blockers, not claims that executing exploits was demonstrated. W2 must also
review integer/address overflow, page-level permissions, section alignment,
zero filling, directory ranges, relocation types and unsupported directory policy.
An accepted metadata result is never an execution authorization.

Do not reuse the Linux CPU through a fabricated Linux process. Any shared CPU
adapter needs a neutral memory/trap callback contract agreed with the Linux owner.
Windows state, imports, handles and policy stay separate. W1 leaves shared code,
legacy PE sources and Linux tests unchanged.

Excluded initially: x86, ARM64, WoW64, GUI/GDI/DirectX, kernel drivers, .NET,
COM/services/registry and arbitrary networking. No performance equivalence or
physical hardware qualification is claimed.

## Reproduction and evidence

```sh
python -m unittest discover -s tests -p test_compact_windows_w1.py -v
PHASE5_SANITIZE=1 python -m unittest discover -s tests -p test_phase5_5_pe.py -v
python scripts/compact_windows_w1.py --output artifacts/compact-windows/w1-audit.json
```

`Compact Windows W1` CI independently builds a freestanding source fixture with
MSVC and runs it on Windows AMD64. Required output is `FLEX_WINDOWS_REFERENCE_OK`
followed by LF, exit 37, empty stderr. The receipt records source/executable hashes,
checkout SHA and platform. Logs/receipts are uploaded; executables and SDK DLLs
are not distributed. This establishes a valid Windows reference, not Flex PE
execution. Both W1 jobs must pass before marking W1 complete.

## Primary technical references

- [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Windows x64 software conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions)
- [GetStdHandle](https://learn.microsoft.com/en-us/windows/console/getstdhandle)
- [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)
- [ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)
