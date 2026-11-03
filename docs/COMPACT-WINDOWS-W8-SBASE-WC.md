<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# W8 — First source-available genuine Windows application: MIT sbase wc

## Original upstream application

Original **sbase `wc`**, an established Unix text-processing program
developed by the suckless contributors, is imported without any modification
from [michaelforney/sbase at immutable commit
`b30fb56804bfed69b45ef0e944d2e029e4d26258`](https://github.com/michaelforney/sbase/tree/b30fb56804bfed69b45ef0e944d2e029e4d26258).

Four original upstream files — `wc.c`, `arg.h`, `utf.h` and the
unabridged `LICENSE` — are retained in
`tests/fixtures/windows_w8_sbase_wc/upstream/`. The complete original
MIT license stays with the copied source. The exact Git blob object IDs are
hard-coded in `scripts/compact_windows_w8_sbase_wc.py` and re-verified
before any compilation. The upstream program, source version and license
must never be silently swapped or auto-synced.

## Actual Windows-host reference

`scripts/compact_windows_w8_sbase_wc.py` compiles the *unmodified upstream
`wc.c`* using the Windows Server 2022 runner's installed Microsoft x64
MSVC toolchain. A separately authored `bridge.c` and `util.h` supply
the small portable `sbase` I/O and argument subset. The bridge deliberately
supports **ASCII only**. It is NOT a replacement for upstream sbase Unicode
support; a non-ASCII input is explicitly rejected rather than silently
giving incorrect word/character counts.

Four named binary executions on the real Windows host must pass:

| Case | Input | Expected normalized stdout |
|---|---|---|
| Default | `alpha beta\nsecond\n` | `2 3 18\n` |
| `-l` | `a b\nc\n` | `2\n` |
| `-w` | `a b\nc\n` | `3\n` |
| `-c` | `a b\nc\n` | `6\n` |

A negative UTF-8 input must fail closed. The independent Linux job also
compiles and executes the **same exact original upstream C source** with
that bridge, verifies original Git blob IDs and rejects any modified
upstream file.

Windows reference report captures PE SHA-256/size, real Windows/runner
versions, exact upstream Git source and compiler bridge digests, stdout
hashes, the bounded native PE import inventory and explicit missing
Win32/CRT APIs. The compiled executable is not uploaded from the Windows
reference workflow; only JSON evidence is uploaded. The source is
redistributable under the copied MIT license.

## Additional no-CRT Windows PE candidate

The first source-built Windows-host PE with MSVC `/MT` passed all **four**
named `sbase wc` workflows, but measured **80 direct imports / 68 missing**
at 154,624 bytes. This is **not** compatible with the existing 32-import
PE loader limit.

Instead of widening that limit, `win32_mincrt.c` implements a narrowly
scoped `GetStdHandle`, `ReadFile`, `WriteFile` and `ExitProcess`
adapter for the **same byte-for-byte original upstream `wc.c`**, compiled
with MSVC `/nodefaultlib`, `/entry:cw_wc_entry`, and an explicit Kernel32
import library. It builds a second PE and executes the default ASCII
stdin workflow on a real Windows host. Its output must match the original
source-linked `/MT` Windows-host reference. It explicitly fails on
non-ASCII, unsupported file arguments and other dynamic CRT behaviour.
Option parsing for `-l/-w/-c` is presently only qualified for the
original `/MT` build, not the separate no-CRT entry point.

The second PE's import count and unsupported import names are **measured**;
the candidate gets only a *structural investigation* flag, never a native
guest acceptance flag. The fixed Ryzova W3 console grants explicitly lack
`STD_INPUT_HANDLE` currently: a trusted bounded stdin resource, genuine
Windows `ReadFile` semantics and source-built native QEMU runtime must be
implemented and independently verified. Never connect the interpreter to
an untrusted host descriptor or bypass per-application API authorization.

## Native Ryzova status (never conflate with host success)

**No proof of native Ryzova/QEMU guest execution is claimed.** MSVC's
static CRT (`/MT`) may still import more Win32 APIs than the current
32-import PE loader limit, require unsupported module aliases or invoke
unimplemented instructions. That outcome is a real engineering blocker;
do NOT widen limits, forge imports, or forward arbitrary Windows calls
to the host.

All receipts MUST keep `native_guest_execution_qualified=false`,
`transitive_runtime_qualified=false` and
`windows_v1_release_qualified=false`, even when every Windows-host
reference passes. Hardware W9 and ARM64 W7 remain independent.

The **next execution gate** is to use the resulting *actual* PE import
inventory and original Windows compiler output, add only the strictly
required original Ryzova Win32/CRT APIs and load the exact same
source-built PE inside a fresh **source-built Ryzova AMD64/QEMU guest**.
Then compare exact stdin/stdout, exit code, faults, memory and namespace
resource caps against Windows. Do not claim source adaptation is an
unmodified Windows System32 application.
