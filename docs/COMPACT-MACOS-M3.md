# Compact macOS M3

M3 adds a freestanding x86-64 Mach-O fixture built from
`tests/fixtures/macos_m3_guest.S`. The fixture is admitted by its SHA-256.
It uses SysV main argument registers and Darwin-numbered read, write, open
and close traps in the bounded Flex profile.

Run the native launcher as follows:

```rc
compact-macos-m2 guest.macho /tmp/my-grant entry.txt demo
```

The guest receives two argv strings and a single environment entry
`FLEX_NOTE=demo`. The launcher accepts exactly four printable ASCII bytes
for this environment value. Pass `-` in place of the directory to launch
without a file grant. The host process environment is outside the guest ABI.

The grant exposes existing ordinary files directly inside one explicit
directory. The fixture reads four bytes and writes the 14-byte environment
entry at the resulting file offset. The launcher maps a single guest
handle and caps file offsets at 64 KiB. Create, truncate, absolute paths,
dot components and subdirectory traversal are outside this profile.
The native launcher binds the directory in a private namespace and
checks the file identity and server device before using the open descriptor.
This model trusts the launcher operator and the granted 9P server.
The Linux harness pins its directory descriptor, rejects symlinks and
mount crossings with openat2, and rejects files with multiple hard links.

The native evidence job retains the original M2 comparison and checks M3
stdout, exit receipts and exact post-run file hashes. It runs successful
access, a parent traversal attempt and a launch with no directory grant.
The M3 fixture exercises Flex's profile. M2 retains the macOS reference
comparison.
