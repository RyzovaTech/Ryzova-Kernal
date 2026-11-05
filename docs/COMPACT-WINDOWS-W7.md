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
This comparison does not claim native-kernel execution of that fixture.

The pinned jq binary now passes TLS metadata validation and is rejected
at the existing bounded import-table profile. It needs imports across 14
DLL names, including UCRT API sets and SHLWAPI. Those implementations,
compiler startup/unwind/instruction coverage and unchanged jq execution
on a source-built Ryzova Kernel through an input-file grant remain W7
completion requirements. A passing admission-audit job records rejection;
it does not mean jq has executed successfully.

TLS layout and callback semantics follow Microsoft's
[PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section).

[Upstream jq 1.8.1 release](https://github.com/jqlang/jq/releases/tag/jq-1.8.1)
