# W4: namespace-backed Windows file APIs

W4 extends the hosted AMD64 runtime with CreateFileW, ReadFile, CloseHandle,
SetFilePointerEx, GetFileSizeEx and FlushFileBuffers. WriteFile now supports typed
file handles as well as W3 console handles. This is stacked on W3 PR #85.
Linux/shared runtime code and shared Compact negotiation remain unchanged.

## Resource boundary

The portable `files.c` core receives directory grants from the trusted launcher:
opaque reference, guest drive letter and read/write/create/metadata/list rights.
`cw_attach_files` copies and freezes at most eight grants. Each namespace belongs
to one machine; attaching it twice or borrowing its pointer from another machine
fails. A guest filename never chooses a provider or supplies a host path.

The `CwFileOps` resource interface provides open/read/write/size/flush/close on
opaque resource identities. A native Flex/9P provider can implement this interface;
**that native transport is not implemented or qualified in W4**. W4 supplies a
real hosted Linux descriptor transport in `files_host.c` to verify the boundary
and persistent bytes. It receives preauthorized directory descriptors, duplicates
them and resolves only beneath those objects. The CLI attaches a C drive only
when the caller explicitly supplies a root; it does not implicitly expose cwd,
HOME or host drive letters.

The Linux transport requires openat2 with BENEATH, NO_SYMLINKS, NO_MAGICLINKS and
NO_XDEV. Unsupported kernels fail closed. Every component is opened relative to
an owned directory descriptor. No chdir, global guest-path open or unsafe fallback
is used. Regular files must have one hard link; symlinks, special files and mount
crossings are rejected. Type/link/size/sharing checks occur before truncation.
Open file identity follows the descriptor across renames; the authorized resource
is an object, not a repeatedly resolved host pathname. Root administration and
provider callbacks are trusted; this is not isolation against a malicious host
administrator concurrently modifying mounts or links.

## Exact path profile

Paths use UTF-16 at the API but this W4 profile supports ASCII filenames only.
A fully qualified `C:\dir\file.bin` selects an explicitly granted drive;
`dir/file.bin` or `dir\file.bin` resolves from the C grant root. There is no
mutable current directory and no implicit C grant. ASCII matching is case
insensitive, including on the hosted Linux transport. Case-colliding host entries
are rejected rather than chosen arbitrarily.

Reject: dot segments, UNC/NT/device prefixes, root-relative/POSIX absolute paths,
drive-relative paths such as `C:file`, alternate data streams, DOS device names,
short-name aliases, wildcard/control/non-ASCII characters, repeated separators,
trailing dots/spaces and unsupported Win32 flags. Boundaries are 240 total units,
63 units per component, 16 components and 256 scanned directory entries per
lookup. Parent directories must already exist; directory creation/enumeration,
Unicode case folding, reparse points and network paths are outside this profile.

## Files and handles

File objects have a process-local typed table: 30 slots plus two slots reserved
for standard output/error. New opens carry monotonically increasing generations;
closed handles are never silently reused. Backend resource tokens and guest
handle values are separate. Numeric handle values may coincide in separate
processes, but they resolve only in the owning namespace. Handle exhaustion is
checked before provider creation/truncation. ExitProcess, normal entry return,
opcode/memory faults and instruction exhaustion close all outstanding file
resources; the host provider also has explicit destruction cleanup.

Supported desired access is GENERIC_READ and/or GENERIC_WRITE, or zero for a
metadata-only OPEN_EXISTING handle. Directory grant rights and handle access
both apply. Creation-capable dispositions in this bounded profile require
GENERIC_WRITE. Creating a missing file additionally requires create authority;
writing an existing file does not imply create authority. GetFileSizeEx and
FILE_END seeking require metadata authority. Flush requires a writable file
handle and calls the provider's flush operation.

All five dispositions are supported with these restrictions: CREATE_NEW,
CREATE_ALWAYS, OPEN_EXISTING, OPEN_ALWAYS and TRUNCATE_EXISTING. Existing
CREATE_NEW fails with error 80; successful existing CREATE_ALWAYS/OPEN_ALWAYS
reports 183. Sharing supports FILE_SHARE_READ/WRITE with symmetric access/share
checks before any truncation. The hosted provider checks object identity across
all namespaces deliberately attached to that same provider. It does not impose
Win32 share modes on unrelated host programs or independently constructed
provider instances. Concurrency/multithreaded provider use is not qualified.

ReadFile/WriteFile are synchronous, with NULL overlapped and a required writable
DWORD count pointer. Full spans and rights are validated before provider I/O.
Reads report actual bytes and successful zero-byte EOF. Each handle has its own
position; seeks support BEGIN/CURRENT/END and signed distances. Seeking past EOF
does not resize a file; a subsequent write produces zero-filled gaps. Files and
positions are bounded to 64 KiB, as is each I/O call. Larger existing files are
rejected before truncation. Pointer/parameter failures leave position and file
content unchanged (the documented output count may be zeroed).

Only normal file attributes or zero are accepted. Security attributes,
inheritance, templates, async/no-buffering/delete flags, file mappings, directory
handles and registry/COM/network resource paths are unsupported. CloseHandle also
invalidates granted standard output/error handles without changing launch policy.
FlushFileBuffers on a console is rejected. Selected extra error codes are
2 missing file, 3 missing parent, 4 handle quota, 5 denied grant/type/link,
6 invalid/stale handle, 32 sharing violation, 80 existing file, 123 invalid path,
131 negative seek, 183 existing open and 223 file/seek quota.

## Verification

```sh
python -m unittest discover -s tests -p 'test_compact_windows_w*.py' -v
PHASE5_SANITIZE=1 python -m unittest discover -s tests -p test_phase5_5_pe.py -v
```

W4 tests cover persistent reads/writes, EOF, signed seeks and sparse gaps,
all dispositions, metadata/creation/read/write rights, symmetric sharing,
independent offsets, generation/quota, cleanup, two isolated namespaces and an
explicitly shared provider, drive mapping, malformed paths, symlink/hardlink and
special-file denial, case collisions, directory scan bounds, API pointer checks,
unsupported flags and source/result receipt validation. UBSan is enabled.

CI independently compiles/runs a freestanding C fixture with MSVC on Windows,
then runs **that identical PE** in the hosted Flex runtime against a fresh
explicit directory grant. Both must create/write/flush/seek/read/reopen the same
file, reject stale handles and CREATE_NEW on an existing file, output the exact
marker and exit `0x23456789`. The final persistent bytes must be
`FLEX_WINDOWS_W4_FILE_OK` + LF + three zero bytes + `!`; their SHA256 is verified
against the Windows receipt. All six new exports and the existing WriteFile path
must actually be exercised, with zero open provider files after execution.

W1's request checker is still a shape validator; it does not issue capabilities.
Native Flex namespace integration, QEMU/hardware qualification and broader
workloads remain later phases. No general Windows filesystem compatibility or
physical durability guarantee is claimed.

References: Microsoft [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile),
[SetFilePointerEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointerex),
[GetFileSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesizeex),
[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle),
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers),
and [Linux openat2](https://man7.org/linux/man-pages/man2/openat2.2.html).
