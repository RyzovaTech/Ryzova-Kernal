# Compact macOS M1

M1 defines a metadata admission profile for thin little-endian x86-64
Mach-O `MH_EXECUTE` files. The planner accepts non-PIE images with a
single `LC_MAIN` and one or more bounded segments. The entry file
offset must resolve to exactly one file-backed executable segment.

The planner enforces the lower 48-bit canonical user half from
`0x10000` up to but excluding `0x800000000000`. Every segment must fit
in the interval. Segments must be disjoint at 4 KiB page granularity.
Both initial and maximum protections exclude a writable executable
segment. Section records are checked for command size and count.
The planner consumes segment mappings only. It does not authorize
section-level relocations or other section semantics.

The permitted metadata commands are `LC_UUID`, macOS
`LC_BUILD_VERSION`, and `LC_VERSION_MIN_MACOSX`. Their encoded
lengths are validated. The hosted probe accepts files up to 4 MiB.
The limits in the plan are specific to this profile and probe.
An execution profile will need its own aggregate guest memory,
instruction and resource policies before launching any input.

The macOS CI job builds and runs the project-owned x86-64 CLI fixture.
It records stdout, stderr, exit status, executable and source hashes,
and the Mach-O header, load commands, dylibs and undefined symbols.
This reference uses the platform toolchain's normal dynamic link path.
Its inventory informs the next loader milestone. The reference job
runs on macOS and does not exercise execution on Flex.
