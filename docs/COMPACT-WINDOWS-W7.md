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
additional threads, dynamic TLS allocation and DLL loading are not yet
implemented. This is an initial-thread startup profile, not full TLS.

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
The existing 32-import and 28-API limits remain in effect.

Only exact DLL contracts and their selected exports are recognized:

| Contract | Selected exports |
| --- | --- |
| `kernel32.dll` | Existing Windows API exports |
| `ucrtbase.dll` | Existing 13 CRT exports |
| `api-ms-win-crt-heap-l1-1-0.dll` | `malloc`, `calloc`, `realloc`, `free` |
| `api-ms-win-crt-private-l1-1-0.dll` | `memcpy`, `memmove`, `memcmp` |
| `api-ms-win-crt-string-l1-1-0.dll` | `memset`, `strlen`, `strcmp`, `strncmp`, `wcslen` |
| `api-ms-win-crt-runtime-l1-1-0.dll` | `_errno` |

These aliases resolve to the same existing canonical API IDs and require
the same explicit grants. No API is newly authorized, no arbitrary API-set
prefix is accepted, and no host DLL is loaded. Unimplemented exports and
wrong-module bindings fail admission before any guest instruction.

An additional reproducible executable calls 15 APIs through all six DLL
names and checks allocation, zero-fill, resizing, copying, string lengths,
private errno state and last-error state. Its expected exit is 37 with no
output. CI compares identical bytes on Windows and the hosted interpreter;
unit tests execute it at three load bases. The native job also runs these
bytes and verifies exact API call counts alongside the TLS gates.

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
