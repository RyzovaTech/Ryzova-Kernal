# Compact macOS M6

The same assembly source builds Intel and Apple Silicon Mach-O PIE
executables. Both use argv and envp to choose a filename and the content
to write. The only admitted imports for this profile are the four strong
libSystem bindings for open, read, write and close.

Use `compact-macos-m2 --files-x86 binary root name demo` or
`compact-macos-m2 --files-arm64 binary root name demo`. The shared bridge
injects one `FLEX_NOTE` entry with a four-byte value and grants an existing
ordinary file through the existing basename-only directory provider.
A dash in place of the root removes the file grant. The bridge has one
guest handle, a 256-byte transfer limit and a bounded guest stack.
The chosen file must begin with four bytes. The fixture writes the
14-byte environment string at offset four and preserves file bytes past
that write. The profile uses the M3 provider's launcher and server trust
boundary and the M4/M5 PIE segment constraints.

The macOS reference jobs run each executable in a fresh working directory.
The hosted harness and source-built AMD64 Flex QEMU guest compare those exact
binary bytes, stdout, exit status and resulting file content. Tests cover
parent traversal and missing grants on both architectures. The hosted
harness also tests a symlink to an outside file. ARM64 here is the guest
architecture.
