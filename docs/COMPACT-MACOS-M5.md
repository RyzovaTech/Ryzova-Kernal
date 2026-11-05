# Compact macOS M5

`compact-macos-m2 --arm64 guest.macho` selects the ARM64 CLI profile. The
launcher interprets ARM64 guest instructions in the Flex process. The CI
qualification uses the source-built AMD64 Flex kernel under QEMU and a
separate Apple Silicon macOS runner for the reference.

The profile uses the dynamic Mach-O loader's segment and chained fixup
validation, with 16 KiB Mach-O pages and ARM64 CPU type validation. The
loader recognizes the reference's embedded code-signature container as
metadata. It does not authenticate Apple signatures. The ARM64 guest ABI
uses X0, X1 and X2 for the bounded `_write` bridge, X30 for the return link
and a private 16-byte-aligned stack. The interpreter supports the
instruction forms needed by the selected CLI and its import stub, with a
64-instruction budget. The fixture reads a rebased pointer to its text.

CI builds and runs the project-owned ARM64 assembly fixture on Apple
Silicon. Hosted and Flex tests then run the same binary bytes. The Flex
receipt requires matching stdout and exit status, one applied rebase and
one import call. This profile covers ARM64 Mach-O CLI bring-up with one
console import. General Apple Silicon application support and qualification
on an ARM64 Flex host are separate work.
