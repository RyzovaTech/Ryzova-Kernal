# Compact Linux symbolic links

The jobs profile implements guest symbolic links in its bounded writable `/tmp`
tree. Links resolve paths inside the guest namespace, including explicitly granted
immutable files and executable images. They never resolve host paths or add a
resource grant. This does not complete general Linux compatibility or add live
host filesystem mounts.

Implemented AMD64 Linux operations are `symlink` (88), `symlinkat` (266),
`readlink` (89) and `readlinkat` (267). Path-based open, stat, chmod, truncate,
access, chdir, directory-relative operations and exec use guest link resolution.
`lstat`, `AT_SYMLINK_NOFOLLOW`, `O_NOFOLLOW`, exclusive creation, unlink, rmdir,
rename and directory enumeration distinguish the link from its target. Readlink
returns a truncated byte string without adding a NUL terminator. Link permissions
are 0777 independently of umask; parent directory search permissions still apply.
`utimensat` can update either the link or its target.

Resolution checks each directory before consuming a component, including `.` and
`..`. Relative link targets start at the containing directory, absolute targets
start at the guest root. Missing intermediate directories cannot be bypassed by
`..`. At most 40 links may be followed in one resolution; additional traversals
return ELOOP. The existing 255-byte path/target limit, 32-node tree and 64-KiB file
limit remain. Dangling and cyclic links may be stored; their targets are checked
when followed. Mutation of a final symbolic link with a trailing slash is checked
without accidentally removing or renaming its directory target.

Explicit image grants take precedence over a same-named node restored from a
snapshot. Links cannot make a granted image writable. Execution through a link
still requires the resolved image to have an explicit execution grant. Guest
paths absent from the namespace fail even when an identically named host file
exists. Hardlinks, O_PATH, procfs magic links, ownership changes, live mounts and
arbitrary Linux applications remain unsupported.

## Saved namespaces

New snapshots use `FLEXFS2\n`; valid `FLEXFS1\n` snapshots remain readable.
The bounded header, checksum, record sizes and timestamp/inode validation are
unchanged. The record word at offset 12 is now a node type: 0 regular file,
1 directory, 2 symbolic link. Version 1 accepts only 0 and 1. Link data is its
nonempty, non-NUL target bytes, at most 255 bytes. Invalid types, empty/oversized
or embedded-NUL targets, and parents that are links instead of directories are
rejected before guest execution. Version 1 readers must reject version 2 output.

## Qualification

`tests/test_phase9_symlinks.py` compares compiled application workloads directly
with Linux, exercises snapshot reload and malformed input, runs ASan/UBSan, and
executes unmodified pinned BusyBox `ln`, `readlink`, `cp -P`, `cat` and recursive
`rm`. The immutable grant case permits Linux's ETXTBSY alongside the guest's
EACCES: both deny modification of the running granted executable.

`scripts/phase9_symlinks.py` requires independent source-challenged native runs,
fixture SHA256 checks, saved-link reload, unmodified BusyBox results and clean
VM completion counts. The source-built AMD64 QEMU workflow must pass this gate;
portable host tests alone do not establish native kernel qualification. Exact
source/run evidence belongs to the corresponding PR, not a generic completion
claim. Physical hardware and operational ARM64 remain unqualified.
