# Compact Windows W7 baseline

The first workload uses the upstream jq 1.8.1 AMD64 Windows executable.
The CI downloads the release asset, checks its published SHA-256 and runs
it on Windows against a fixed JSON input. The exact same executable is
then passed to the existing Ryzova Kernel Compact Windows image planner
in a hosted audit. The audit captures the PE inventory and admission
result. It does not execute the image in Ryzova Kernel.

The workload reads an existing file and reports the item count and sum.
The W7 execution gate will compare the same executable's stdout, stderr
and exit status while it reads the input through a Ryzova directory grant.
The planner now accepts an opaque resource directory only within the
file-backed virtual extent of a read-only, non-executable `.rsrc` section.
It bounds the directory header and root entry array. Resource entries are
never followed and resource lookup APIs are outside this profile. The
admission audit identifies the first unsupported PE data directory.

## TLS startup profile

The loader validates PE32+ TLS VAs against this image before allocating
or executing anything. The profile supports one image and its initial
thread, a template plus zero fill of at most 4096 bytes, and at most eight
ordered process-attach callbacks. Directory and callback-array bytes must
be file backed and read only; callback entry addresses must be backed
executable bytes. The TLS index must be aligned writable data outside the
IAT. Reserved characteristics and alignments above 4096 are rejected.

The lower 8192 bytes of the existing 65536-byte guest stack arena hold a
minimal TEB, a TLS vector with slot zero, and the private template copy.
The TEB provides self, stack bounds and the static TLS vector pointer.
It does not provide a complete PEB/TEB or additional threads. GS memory
operands resolve through guest memory checks; LEA ignores the GS base.
TLS bytes are non-executable. Each machine owns its own copy.

Callbacks receive the image base, DLL_PROCESS_ATTACH (1), and a zero
reserved argument. They execute through the same interpreter, import
policy and instruction budget as the entry point. A balanced synthetic
return advances to the next callback, then to the application entry.
Callback faults or budget exhaustion stop startup. Detach callbacks,
additional threads and DLL loading are not yet implemented. Dynamic TLS APIs described below
operate on the same initial thread. This is not a multithreaded profile.

The reproducible TLS fixture checks callback arguments/order and accesses
static TLS through GS. CI runs identical executable bytes on Windows and
the hosted Ryzova interpreter at three load bases, separately from jq.
This comparison is separate from the native TLS job. That job builds the
runtime and kernel with native 6c/mk, independently checks the installed
kernel hash, reboots and checks source-built guest identity and runtime
hashes. It executes the identical Windows TLS fixture plus callback-fault,
instruction-budget and invalid-callback admission cases. Its receipt
records TLS startup qualification separately from jq/W7 completion.

## Import directory and selected API-set contracts

The import directory can include names and thunk tables after its null
descriptor. The loader bounds the complete directory to 65536 file-backed
bytes and the descriptor scan to 16 modules plus a terminator. It checks
every lookup/IAT span, disallows descriptor/thunk overlap, rejects duplicate
modules and API bindings, and protects the aggregate IAT after binding.
The import ceiling is now 256. The runtime registry lists the exports available to an explicit launch grant.
Unregistered IDs cannot be granted or dispatched.

Only exact DLL contracts and their selected exports are recognized:

| Contract | Selected exports |
| --- | --- |
| `kernel32.dll` | Existing Windows API exports |
| `ucrtbase.dll` | Existing 13 CRT exports |
| `api-ms-win-crt-heap-l1-1-0.dll` | `malloc`, `calloc`, `realloc`, `free` |
| `api-ms-win-crt-private-l1-1-0.dll` | `memcpy`, `memmove`, `memcmp` |
| `api-ms-win-crt-string-l1-1-0.dll` | `memset`, `strlen`, `strcmp`, `strncmp`, `wcslen` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | `_errno` |

These aliases resolve to the same canonical API IDs and require
the same explicit grants. No arbitrary API-set
prefix is accepted, and no host DLL is loaded. Unimplemented exports and
wrong-module bindings fail admission before any guest instruction.

An additional reproducible executable calls 15 APIs through all six DLL
names and checks allocation, zero-fill, resizing, copying, string lengths,
private errno state and last-error state. Its expected exit is 37 with no
output. CI compares identical bytes on Windows and the hosted interpreter;
unit tests execute it at three load bases. The native job also runs these
bytes and verifies exact API call counts alongside the TLS gates.

## Extended grants and startup state

The native runtime's internal C layout is version 2 and must be rebuilt.
The low mask keeps all previous API IDs and grants; seven additional
32-bit words provide storage for up to 256 IDs. All grant words are checked
against the implemented registry, and dispatch checks both the declared
import and the launch grant using its full ID. Unknown bits fail closed.
The original JSON contract profiles are unchanged; this native C/CLI
extension does not silently extend their advertised export lists.

The native CLI still grants only the original 28 APIs by default. `-a`
sets the low word and `-A` explicitly supplies word one. Use
`-g word:mask` for words two through seven. Reserved bits remain zero. New APIs, including those at IDs 31/32, cannot acquire
permission through truncation or a legacy launch mask.

Seven new kernel32 exports have stateful implementations:

| Exports | Behavior |
| --- | --- |
| `AreFileApisANSI`, `SetFileApisToANSI`, `SetFileApisToOEM` | Per-environment mode, initially ANSI; wide file APIs are unaffected. Narrow file-path conversion is not implemented. |
| `TlsAlloc`, `TlsFree` | A bounded 64-slot index pool for the initial thread; zero on allocation/reuse; free releases the index and never frees the stored pointer. |
| `TlsGetValue`, `TlsSetValue` | Opaque 64-bit values isolated per environment; valid base-range reads clear last-error, including zero values. Out-of-profile indices fail with error 87. |

Pool exhaustion returns `TLS_OUT_OF_INDEXES` with error 8. Slots are not
shared with the image's static TLS template/vector, and no additional
threads or direct dynamic-TLS TEB layout are claimed. The file mode is
guest state and never changes the host's file API mode.

A new identical-bytes Windows/hosted/native fixture checks mode changes,
multiple TLS values, zero retrieval versus error, and index release/reuse;
its expected exit is 41. Hosted and native launch tests require explicit
low and high grants and reject missing words before guest allocation or
execution. Native receipts also verify exact API call counts.

Semantics are based on Microsoft's [TLS allocation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsalloc),
[TLS reads](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue),
[TLS release](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsfree),
and [file API mode](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-arefileapisansi)
documentation. Capacity and single-thread restrictions are Ryzova profile limits.

## Synchronization objects and virtual identities

Seventeen further kernel32 exports implement events, semaphores, waits,
critical sections, current-process/thread identities and handle duplication.
Objects are private to the environment: up to 32 objects, 64 generation-tagged
handles and 32 critical sections. File and synchronization handle families
are disjoint; no handle is a host pointer or host OS handle.

Manual-reset events remain signaled until reset. Auto-reset waits consume one
signal; repeated SetEvent calls do not accumulate signals. Semaphores enforce
initial/maximum/release bounds and write previous counts only on successful
release. Wait-all validates the entire input and consumes all signals together;
wait-any selects the first ready object. Invalid inputs do not consume state.
This profile rejects duplicate object references in one multiple wait.

Ready waits complete immediately for any timeout. Unready zero-timeout waits
return WAIT_TIMEOUT. Unready positive/infinite waits halt with CW_API because
the profile has no scheduler; they never report fabricated completion or
elapsed time. Named objects and security descriptors return error 50.

DuplicateHandle supports the current virtual process, preserves object lifetime
through independent references, and attenuates access. DUPLICATE_CLOSE_SOURCE
closes a valid source even if duplication fails, preserving the operation's
error. File-handle duplication is unsupported, but its close-source failure
side effect is honored. Dropped references and reused slots cannot revive a
stale handle. Critical sections support recursion by the initial thread and
mirror the basic Win64 fields; invalid lifecycle, pointer and capacity cases
stop rather than pretending to acquire a lock. No multithreaded locking is claimed.

GetCurrentProcess/GetCurrentThread return virtual pseudo handles. Both virtual
IDs are 1 inside the private initial-process/thread namespace. These are not
host IDs and are separate from the independently checked native kernel identity.
Pseudo handles can be duplicated to private process/thread handles, which stay
unsignaled while that initial process/thread is alive.

The synchronization executable expects exit 43 and checks events, semaphore
counts, wait-all/any, duplicate lifetime and close-source-on-error, pseudo
handles, and critical-section recursion. Windows, hosted and native jobs use
identical bytes; hosted/native receipts require exact API call counts. Separate native gates reject
missing synchronization grants and stop an unsupported infinite blocking wait.

See Microsoft's [event objects](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects),
[semaphores](https://learn.microsoft.com/en-us/windows/win32/sync/using-semaphore-objects),
[DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
and [critical sections](https://learn.microsoft.com/en-us/windows/win32/sync/critical-section-objects).

The pinned jq binary now passes resource/TLS validation and its import
directory's descriptor layout; it is rejected for unimplemented imports.
It needs imports across 14 DLL names, including additional UCRT API sets
and SHLWAPI. The remaining export implementations,
compiler startup/unwind/instruction coverage and unchanged jq execution
on a source-built Ryzova Kernel through an input-file grant remain W7
completion requirements. A passing admission-audit job records rejection;
it does not mean jq has executed successfully.

TLS layout and callback semantics follow Microsoft's
[PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section).

[Upstream jq 1.8.1 release](https://github.com/jqlang/jq/releases/tag/jq-1.8.1)


## W7.1 hosted startup checkpoint

Run the following from a repository checkout, using the SHA-pinned executable
from the Windows reference artifact:

```sh
python3 scripts/compact_windows_w7_trace.py path/to/jq.exe --require-startup --out artifacts/w7-audit
```

The trace uses an explicit diagnostic profile, a bounded instruction budget,
and a read/seek directory grant. It admits unresolved named imports as stop
tokens. Calling one halts the machine and records the import, while ordinary
launches still reject unresolved imports during admission. The trace accepts
bounded read-only exception metadata as data. It does not deliver exceptions
or unwind guest frames. The native launcher selects the profile with
`-P trace` and accepts a separate ASCII Windows command line via `-c`.

The startup gate checks that the pinned image executes its CRT initializers,
configures wide arguments, converts them to UTF-8 and reaches semaphore calls.
The recovered checkpoint stops at `LOCK ADD` at guest address `0x140082218`
after 1,239 counted steps. The hosted receipt keeps startup evidence separate
from query output parity and native qualification. Its source commit, input
and binary hashes, API counters and stopping address are included in the CI
audit artifact.
