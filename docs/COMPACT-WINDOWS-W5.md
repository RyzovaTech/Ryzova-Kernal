# W5: named compiler/selected CRT workloads and explicit failure classes

W5 freezes `console-ucrt-selected-v1` in `ryzova/compat/windows/w5-profile.json`.
The additive request version is API 1.1 with the existing Windows AMD64 ABI.
The original `console-win32-v1` remains API 1.0 and continues to reject CRT imports.
Both Python validators remain shape-only: validation does not grant authority or
start a process. The concrete hosted C launcher still receives explicit policy.

This phase is stacked on W4 PR #86. Linux/shared runtime and the old PE metadata
planner remain unchanged. Native Flex kernel, 9P transport and hardware proof
remain W6. W5 is a finite compiler/CRT profile, not full Windows/UCRT support.

## Frozen workloads

| Name | Source behavior | Required evidence |
| --- | --- | --- |
| buffers | Real imported UCRT memory/string operations including overlap-safe move and UTF-16 length | Exact stdout and exit 0x34567891; all eight named routines called |
| heap | calloc zero-fill, malloc, realloc data preservation, explicit free and recoverable overflow/errno | Exact stdout and exit 0x34567892; all named heap routines called |
| integer | Compiler-produced 64-bit multiply/rotate/variable divide loop plus signed quotient/remainder | Exact stdout and exit 0x34567893 after independent arithmetic checks |
| divide-zero | Runtime integer divisor is zero | Windows 0xC0000094 maps to guest integer-divide-error, no successful exit |
| access-fault | Runtime pointer is NULL | Windows 0xC0000005 maps to guest memory-fault, no successful exit |
| illegal-instruction | Compiler emits UD2 | Windows 0xC000001D maps to guest unsupported-opcode, no successful exit |

Every executable comes from the supplied C source with a distinct W5_CASE define.
The Windows test uses MSVC /O1 /Oi- /Ob0 /GS- without CRT startup. A generated
metadata-only import library selects exports from the real OS `ucrtbase.dll` on
Windows. That import library and Microsoft DLLs are not transferred to Flex.
Each identical PE, its SHA256 and native result are compared with hosted execution.
Using the OS CRT in the reference does not mean Flex loads or executes that DLL.

## Selected exports and memory ownership

Only two DLL names are admitted: kernel32.dll and ucrtbase.dll, each with its own
exact export list and at most one descriptor. The existing 15 Win32 exports remain.
The 13 CRT additions are memcpy, memmove, memset, memcmp, strlen, strcmp, strncmp,
wcslen, malloc, calloc, realloc, free and _errno. Ordinals, duplicate descriptors,
duplicate exports, wrong-module names, API-set aliases, forwarded/bound imports,
other CRT DLLs and dynamic lookup remain unsupported. Aggregate imports are
bounded to 32. Each imported thunk still requires an explicit launch permission.
All IAT arrays and alignment gaps remain protected from guest writes/relocations.

CRT implementations use checked guest memory and private allocator state. They
never forward a guest pointer into a host CRT call. Buffer operations validate
full spans before mutation, are limited to 64 KiB per call and return the guest
destination address where required. memmove supports overlap; overlapping memcpy
is a profile contract violation. Comparisons use unsigned bytes and return the
standard signed ordering result. Strings are scanned only through readable guest
memory, with a 64 KiB scan ceiling; wcslen counts 16-bit units, not Unicode graphemes.
Unterminated/inaccessible strings and invalid buffer contracts stop the guest.
Zero-length buffer/strncmp operations do not dereference their pointers.

The CRT allocator shares the existing 1 MiB private backing pool with VirtualAlloc,
with at most 16 live CRT allocations and the existing 16 reservation slots total.
Each allocation reserves a page-rounded region at the provider's allocation
alignment. This is intentionally less space-efficient than a production CRT heap.
No guest allocation calls the host allocator. calloc checks multiplication before
allocation and zero-fills fresh memory. realloc preserves the original on failure,
can resize within existing page capacity, and otherwise copies before releasing
the old region. Successful realloc may return a different address.

malloc(0) returns a freeable allocation in this profile; free(NULL) is harmless;
realloc(NULL,n) allocates, and realloc(p,0) frees p and returns NULL. Failed size,
capacity or allocation-table requests return NULL and set private errno=12
(ENOMEM). _errno returns a four-byte writable guest address, isolated per machine
and independent of Win32 GetLastError. Successful CRT calls preserve errno.

Only CRT-owned base pointers can be freed/reallocated. Invalid/interior/double
free stops with crt-contract. Win32 VirtualFree/commit cannot invalidate CRT-owned
blocks; CRT free cannot release a VirtualAlloc reservation. Immediately freed
pages are inaccessible; an old C pointer can alias a later allocation at the same
address, as with ordinary C allocators. No permanent stale-pointer detection or
object-level memory-safety guarantee is claimed.

## Instruction inventory and faults

The profile adds signed/unsigned multiply/divide, immediate and two-operand IMUL,
TEST/NOT/NEG, shifts/rotates, sign-extension moves and accumulator sign extension.
Exact opcode families are listed in the machine-readable profile. Arithmetic is
implemented with unsigned operations and a bounded wide-division algorithm;
guest divide-by-zero/quotient overflow never executes a host division fault.
Register/flag results are tested independently against Python integers, including
8/16/32/64-bit widths and signed remainder semantics. Only defined flags are
qualified. Floating point, AVX, ADC/SBB and other unlisted instructions are not
implicitly enabled by this work.

Stop classes now include integer-divide-error (11) and crt-contract (12), alongside
existing memory, opcode, budget, ABI and policy failures. Receipts include the last
guest instruction address even when failure occurs inside a trusted thunk. A fault
terminates this machine; faulted instructions are not resumable. File resources
continue to close on stop through the existing cleanup path. Native Windows
NTSTATUS values are classified against the corresponding guest stop, rather than
misrepresented as successful DWORD application exits.

No SEH handler dispatch, stack unwinding, C++ exceptions, CRT startup/stdio/locale,
signals, threads or synchronization library is implemented. The single-thread
profile does not claim multithreaded runtime compatibility. Normal handler-free
unwind metadata remains structurally validated as in W3.

## Reproduction

```sh
python -m unittest discover -s tests -p 'test_compact_windows_w*.py' -v
PHASE5_SANITIZE=1 python -m unittest discover -s tests -p test_phase5_5_pe.py -v
```

Unit tests cover the additive contract, DLL/export separation, permissions/IAT,
CRT buffers/strings, zero-length and bad-pointer cases, allocator ownership,
overflow/OOM/realloc recovery, errno isolation, arithmetic/flags and failure
receipts. UBSan and earlier import/PE mutation corpora remain enabled. This is
finite conformance evidence, not exhaustive ISA/CRT certification.

CI builds and runs all six Windows references with crash dialogs suppressed by
the trusted test launcher, then runs those identical PEs on Ubuntu in hosted Flex.
Success markers, exits, actual selected CRT call counts, source/executable hashes
and all three native fault classifications must match. Only project fixture
executables and receipts/logs are published. Native Flex/QEMU remains explicitly
unqualified in every suite receipt.

Primary references: [Microsoft CRT memory allocation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/memory-allocation),
[buffer manipulation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/buffer-manipulation),
[UCRT deployment](https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment),
[errno](https://learn.microsoft.com/en-us/cpp/c-runtime-library/errno-doserrno-sys-errlist-and-sys-nerr),
and [Intel instruction manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).
