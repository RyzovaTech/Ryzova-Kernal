# W3: explicit Windows API imports in the hosted runtime

W3 implements nine kernel32 exports for the existing bounded AMD64 console
profile. It is stacked on W2 PR #84, which is stacked on W1 PR #83. Linux,
shared CPU code and shared Compact negotiation remain unchanged. Native Flex
kernel/QEMU qualification remains W6. This is not general Windows compatibility.

W4 extends this historical phase baseline with file handles and explicit drive
grants; see `COMPACT-WINDOWS-W4.md` for the additional current behavior.

## Admission and calls

The loader accepts one unbound `kernel32.dll` import descriptor with an in-range
zero terminator, bounded ASCII names, backed ILT/IAT entries, matching lookup
values and at most 32 imports. DLL casing is normalized; export casing is exact.
This implementation has nine unique exports, so at most nine distinct imports
can currently resolve. Ordinals, duplicate exports, other DLLs, forwarded/bound
imports, delay imports and dynamic lookup are rejected. If OriginalFirstThunk is
zero, the unbound FirstThunk lookup is supported. The advertised IAT range, when
present, must match the table. Section/header/address admission remains strict.

The loaded IAT contains exact Flex-owned numeric thunk tokens. Those tokens never
become host pointers. Every dispatch requires the API to be both declared in the
image and enabled by the trusted launch policy. IAT writes and overlapping DIR64
patches are denied. There is no host DLL loading, DLL search or host syscall
forwarding. Each thunk consumes an instruction-budget step and validates Win64
stack alignment, shadow space and arguments, including WriteFile's fifth argument.

Ordinary bounded version-1 unwind descriptions with no handlers/chains are now
admitted because compiler-generated functions use them. Function ranges, backing,
code offsets and supported unwind encodings are checked. This enables normal
execution, **not exception dispatch or stack unwinding**. Handler/chained/version-2
metadata remains unsupported. Inert debug metadata continues to be bounded.

## Implemented exports and supported forms

| Export | W3 behavior |
| --- | --- |
| GetStdHandle | Per-launch stdout/stderr handles only when explicitly granted; absent stdin returns NULL; bad selector returns INVALID_HANDLE_VALUE and error 87 |
| WriteFile | Synchronous writes to those two handles; full buffer/count-pointer validation; NULL overlapped required; exact bytes and DWORD written count |
| ExitProcess | Ends this single-thread guest with the complete unsigned DWORD code; no API return or synthetic epilogue required |
| GetLastError / SetLastError | Independent per-machine state for the one supported guest thread; DWORD-sized values |
| GetCommandLineW | Stable read-only UTF-16 raw command line supplied explicitly by the launcher; no argv/CRT parsing |
| GetEnvironmentVariableW | Explicit environment only; ASCII variable names compared without ASCII case; UTF-16 values, size query, small-buffer required-size return and missing-variable error |
| VirtualAlloc | Private bounded heap; NULL-address reserve/commit, aligned explicit reserve and in-reservation commit; zero fill; no executable protection |
| VirtualFree | MEM_RELEASE at exact allocation base with size zero, and bounded MEM_DECOMMIT/recommit; freed/decommitted pages become inaccessible |

No API reads host environment variables or host filesystem paths. The launcher
attaches console grants separately from API permission: an enabled WriteFile API
alone cannot obtain output authority. Handle values belong to a process's table;
the same numeric value in another process resolves only within that other
process's grants. Output is captured for the launcher, not streamed to arbitrary
host endpoints. File handles and namespace-backed files are W4.

API failures return their Windows-shaped failure value and set last error;
guest memory faults during ordinary instructions still terminate the machine.
Success normally preserves last error; an existing empty environment value clears
it so zero can be distinguished from a missing variable. Selected errors are
6 invalid handle, 8 resource quota, 50 unsupported asynchronous form,
87 invalid parameter, 203 missing environment value, 487 invalid address and
998 inaccessible API buffer. This is a documented subset, not exhaustive Win32
edge-case compatibility.

## Bounds and launch policy

A trusted C caller provides `CwLaunch`, `CwServices` and heap backing to
`cw_attach_services` with zero-initialized service state. Configuration is
validated and copied before execution; reattachment and attaching the same
service state to another machine are refused. Every service access checks its
owner, so even a copied service pointer cannot borrow another guest's authority. Image, machine state, policy and heap backing may not
alias guest-writable storage. API/console masks default to zero in the CLI.
Missing imported API permissions are rejected before allocating the execution
arena. The synthetic Python fixtures deliberately attach their explicit test
policy; this does not grant privileges to arbitrary manifests.

Limits: one process/thread; one module; nine supported exports; 1023 command-line
UTF-16 units; 16 environment entries with 63-unit ASCII names and 255-unit UTF-16
values; 64 KiB per WriteFile and 64 KiB aggregate stdout/stderr; 1 MiB heap;
16 reservations; 4 KiB pages and 64 KiB reservation alignment. Image, stack,
command mapping and heap together remain within 64 MiB. The arena is allocated
only after admission; input parsing has its separate existing 4 MiB file cap.

Only PAGE_NOACCESS, PAGE_READONLY and PAGE_READWRITE are supported. PAGE_EXECUTE,
VirtualProtect, large pages, MEM_RESET, arbitrary mappings and unaligned explicit
reservation requests are refused. Reserve-only pages are inaccessible; committing
fresh or decommitted pages zeroes them; repeated commit preserves existing data
and protection. Read-only mappings cannot be made writable by recommitting them.
The heap never becomes executable. Capacity is preallocated by the trusted caller,
so guest API requests do not invoke a host allocator. Commit/release accesses are
checked across every page and allocation boundary.

W1's Python request-shape validator remains an offline contract checker. It does
not attach capabilities or start this runtime. The standalone C launcher now
provides the concrete W3 execution path; connecting shared negotiation and the
full candidate resource policy is still separate work. W4 exports remain planned.

## Verification

```sh
python -m unittest discover -s tests -p 'test_compact_windows_w*.py' -v
PHASE5_SANITIZE=1 python -m unittest discover -s tests -p test_phase5_5_pe.py -v
python scripts/compact_windows_w3.py
```

The W3 tests exercise imports/IAT, denied authority, two-environment isolation,
API pointers, aggregate output quota, UTF-16 including Sinhala and surrogate
pairs, name matching, last-error state, reserve/commit/decommit/recommit/release,
protection, invalid sizes/flags, use-after-free, thunk forgery, stack ABI,
configuration aliasing, metadata and receipt provenance. UBSan is enabled. A
600-image import mutation corpus supplements W2's 400-image corpus; neither is
an exhaustive fuzzing/security claim.

CI compiles the supplied freestanding C source with MSVC, runs it on Windows
AMD64 with `--w3-test "two words"` and the explicit `FLEX_W3_PROBE=ready` value,
then transfers that **identical PE** to Ubuntu. It must exercise all nine imports,
produce exact stdout `FLEX_WINDOWS_W3_OK` plus LF, exact stderr
`FLEX_WINDOWS_W3_STDERR` plus LF, and exit `0x12345678` on both systems.
Executable paths differ between launchers; the fixture checks the declared raw
argument within each command line, not path equality. Receipts verify checkout,
source/executable hashes, platform, outputs, exit and every API call. Artifacts
contain the project's own fixture executable and receipts/logs, no SDK DLLs.

Microsoft primary references:
[PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile),
[GetCommandLineW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew),
[GetEnvironmentVariableW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew),
[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc),
[VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree),
[ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess).
