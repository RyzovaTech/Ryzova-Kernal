# Compact macOS M4

`compact-macos-m2 --dynamic guest.macho` selects the M4 profile. Admission
checks the Mach-O structure instead of matching a fixture digest. The profile
accepts thin x86-64 PIE executables with PAGEZERO followed by one page each
for TEXT, DATA_CONST and LINKEDIT. TEXT is the execution and stdout source.
DATA_CONST is readable by the interpreter after loading. LINKEDIT supplies
loader metadata. The runtime does not map guest bytes as host instructions.

The loader recognizes a single strong `_write` import from
`/usr/lib/libSystem.B.dylib`. It applies bounded format-6 chained binds and
offset rebases in a single DATA_CONST page. The executable can load the
relocated pointer through RIP-relative addressing. The import resolves to
the existing bounded stdout bridge. The interpreter limits execution to
64 instructions and returns an error on unsupported instructions or traps.
The loader accepts the profile's known load commands and validates ranges
before consuming metadata. Apple dylib and dyld binaries are unnecessary
for this implementation.

CI builds the project-owned assembly fixture on Intel macOS. It executes
the resulting binary there and transfers those exact bytes to the Flex
QEMU job. Flex must match stdout and exit code, with one rebase and one
import call recorded. The native job also reruns the original M2 and M3
cases. This profile covers the selected dynamically linked CLI, with
general dyld behavior and additional system APIs outside its scope.
