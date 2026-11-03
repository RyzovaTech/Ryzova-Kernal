<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# W8 — Genuine Windows console application references and import-gap discovery

This increment is on **PR #89**, the same draft W7–W9 integration PR.
It does not merge or modify driver agents, Compact Linux or 9front auto-sync.

## Actual Microsoft Windows applications (not generated test fixtures)

The initial bounded application inventory uses three genuine, unmodified
Windows Server 2022 System32 console programs:

| Application | Exact Windows-host reference | Native Ryzova status |
| --- | --- | --- |
| sort.exe | Sort ASCII orange/apple into apple/orange | NOT executed |
| findstr.exe | Find literal apple prefix in 3 ASCII input lines | NOT executed |
| where.exe | Locate cmd.exe on the Windows PATH | NOT executed |

The CI runner checks real absolute System32 binary paths and executes only
these predefined harmless commands, with bounded input and no shell search.
It records the SHA-256/file size of the actual PE, Windows build and runner
image version, command exit code and stdout digest. **No Windows executable,
Microsoft DLL or SDK content is copied or uploaded**; only JSON reference
evidence is archived.

The existing original Ryzova W8 import parser reports direct/delayed imports,
DLL names, unsupported/ordinal functions and CLR/TLS requirements, or
explicitly reports a bounded parser rejection. Import coverage is NEVER
interpreted as proof of guest execution.

Hosted windows-2022 images are mutable, not immutable binary fixtures.
The reference receipts pin the observed System32 SHA-256 for each CI run,
so upgrades remain visible. A future production fixture needs a
reviewed, source/binary-pinned named application set.

## Explicit non-qualification

All reports carry:
- native_guest_execution_qualified=false
- windows_v1_release_qualified=false
- guest_execution_verified=false for each app
- transitive_dll_closure_verified=false for each app

System32 reference successes do not prove native Ryzova execution, imports'
transitive dependency closure, Win32 CRT/TEB/PEB support, TLS, exception
handling, guest resource budgets, or physical hardware safety.
The existing W6 native QEMU evidence remains separately valid.

## First real Windows Server 2022 execution receipt

The initial exact-branch W8 Windows reference job ran all **three genuine
System32 executables successfully** with expected stdout and zero exit
status. Only JSON evidence was uploaded; see [Windows-host CI run
41661135525](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41661135525).

At that snapshot the current Ryzova declared Win32 import profile covered
**0 of 3** binaries and the strict triage selected **no structurally
eligible first guest candidate**. The later W8 import-gap logger prints
bounded imported module names, missing API samples, binary SHA256 and
explicit parser rejection (when applicable); detailed signed-off provenance
remains in the JSON artifact.

This result is an engineering constraint, **not evidence that the real
System32 applications ran under Ryzova**. Microsoft binaries cannot be
silently redistributed to QEMU. If none of these genuine binaries fits the
bounded native PE loader, choose a separately reviewed **source-available**
Windows console application with reproducible PE build/host reference,
then perform independent native QEMU execution and input/output comparisons.

## Next W8 qualification

Use real missing-import reports to select an achievable genuine application;
implement finite required original Win32 API/CRT services under strict import
authorization and resource grants. Run that same named binary inside
source-built Ryzova AMD64 QEMU with identical args/input; independently
compare output, exit code, handles and resource budgets. Preserve kernel
security, driver and ABI regression CI. W7 native ARM64, W9 physical evidence,
release/hardware/legal approvals and exact-head checks are not waived. Never
merge this draft before the named app guest tests and final release gates pass.
