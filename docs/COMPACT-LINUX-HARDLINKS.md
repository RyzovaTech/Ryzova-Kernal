# Compact Linux hardlinks and shared inode lifetimes

The jobs profile implements AMD64 Linux `link` (86) and `linkat` (265) within
its writable guest `/tmp` filesystem. Multiple directory entries share one inode,
file bytes, permissions and timestamps. Each open file description keeps its own
offset; duplicated/fork-shared descriptions still share an offset as before.
`stat`, `lstat`, `fstat`, directory enumeration and truncation
observe the same underlying inode. `st_nlink` counts the remaining linked names.

Removing the original name does not invalidate aliases. Removing all names does
not invalidate existing open descriptions. A backing slot cannot be reused while
an alias or open description retains it. Aliases reference an inode directly;
alias chains are never created. Renaming one name onto another name for the same
inode succeeds without removing either name. Replacing a different inode updates
that inode's link count and retains its open handles.

Default link operations link a symbolic link itself. `linkat` with
`AT_SYMLINK_FOLLOW` (1024) links its resolved target instead. A relative symbolic
link hardlinked into another directory resolves its target relative to that new
directory, while retaining its shared symlink inode and timestamps. Directory
hardlinks are denied. Both paths use the guest namespace resolver; parent search
and destination write permissions still apply.

This is a bounded guest filesystem, not a host mount. Explicit immutable image
and library grants cannot be hardlinked or replaced. Crossing into protected
resource paths is denied. `AT_EMPTY_PATH`, shared file mappings, O_PATH descriptors and linking
unlinked inodes through procfs are not implemented; unsupported linkat flag bits
return EINVAL. The fixed 32-entry namespace limit remains; aliases consume entries
but do not copy file data or allocate a new inode number.

## Snapshots

Snapshots with multiple names for an inode use `FLEXFS3\n`. Snapshots without
shared names continue to use `FLEXFS2\n`. Valid version 1 and 2 input remains
supported. Version 3 retains the same header, checksum and 80-byte record prefix.
Node type 3 is a hardlink entry with a four-byte little-endian reference to a
canonical data record's slot. Types 0, 1 and 2 retain their existing meanings.

One remaining name represents the canonical data record, even if the original
runtime inode slot has become unlinked. Other names reference that record. Export
does not change live descriptor identities or offsets. Unlinked-only open files
are excluded from the saved namespace, as before. If only one name survives, its
data is exported directly in a version 2 record.

Import validates alias targets, sizes, inode identity, permissions and timestamps
before execution. Missing targets, directory targets, self references, alias
chains, mismatched metadata and independent canonical records with duplicate
inode numbers are rejected. These corruption checks are not authentication or
crash-atomic journaling.

## Verification

Portable tests compare compiled application workloads with Linux for shared
bytes, metadata, offsets, unlink/open lifetimes, rename, directory-relative links,
relative symlink aliases, permission errors, fork sharing and slot churn. Policy
tests check entry quotas and immutable grants. ASan/UBSan, malformed snapshots,
independent reload and checksum-pinned unmodified BusyBox ln/cp -l/stat/cmp/rm
workflows are included.

The native source-build workflow requires 20 successful application invocations,
source challenges, fixture hashes, shared-data reload, single-alias legacy output,
relative symlink reload and the BusyBox workflow. Passing this extension does not
establish arbitrary Linux application compatibility, operational ARM64 or physical
hardware qualification. Exact qualification results belong to the PR/source head.
