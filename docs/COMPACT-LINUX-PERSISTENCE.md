# Explicit persistent filesystem snapshots

The `compact-linux -j` profile can export its bounded `/tmp` tree into a native
file, and restore that tree in a later invocation. Persistence is an explicit
resource grant. Without the new flags, each invocation still starts with an
empty tree.

```
compact-linux -j -W /tmp/environment-001.fs program.elf create
compact-linux -j -R /tmp/environment-001.fs -W /tmp/environment-002.fs program.elf update
compact-linux -j -R /tmp/environment-002.fs program.elf inspect
```

`-R` imports one snapshot. `-W` exports a new snapshot through exclusive create
with permissions 0600. An existing destination is never truncated or overwritten.
Each export is a separate immutable version from this command's perspective;
concurrent updates can produce separate versions without silently replacing a
previous version. The caller manages retention and selecting the next version.
The native paths resolve through the application's Plan 9 namespace. Remote
backing filesystems still need their own operational qualification.

The stored tree includes linked directories/files, data, owner permission bits,
inodes and timestamps, plus the logical clock and next inode. Descriptor tables,
working directories, processes, sockets, library grants and unlinked files are
not restored. Completed filesystem changes are exportable even if the guest
later faults or exhausts its instruction budget. Loader/import failures do not
produce an output snapshot. An export I/O failure makes the CLI fail; it does not
turn guest execution into a successful persistence claim.

The versioned `FLEXFS1` format uses explicit little-endian integers and bounded
variable-length records, not serialized host structs or pointers. It stores only
linked nodes. The importer validates the complete length, version, checksum,
record counts, IDs, inode uniqueness/counter, permission bits, file sizes,
nanosecond fields, parent directories, acyclic connectivity, sibling uniqueness,
name components and full path limits before guest execution. Bad input cannot
supply host paths or serialized file descriptors. The checksum is FNV-1a-64 for
corruption detection; it is not authentication or a cryptographic signature.

Bounds remain 32 nodes, 65536 bytes per file and paths shorter than 256 bytes.
The maximum encoded snapshot is `RYZ_FS_SNAPSHOT_MAX`. The embedding API adds an
optional zero-initialized `RyzFilesystemResources` to `RyzJobConfig`; its output
buffer must fit that maximum. A failed import clears the output size. Output
bytes and new native files are caller-owned resources.

This is snapshot persistence, not a general live filesystem mount, a journal,
power-loss atomic replacement or a promise that guest fsync commits native
storage immediately. General mounts, symlinks, hardlinks and broader filesystem
semantics remain unfinished.

Tests launch independent interpreter invocations for create/reload/append/
rename/delete, preserve the original snapshot, enforce exclusive export, check
permissions and recover completed changes after an instruction-limit fault.
Malformed snapshots with recomputed valid checksums test semantic validation.
The fresh native source-build gate additionally requires six successful native
invocations and rejection of a corrupted grant, source-specific challenges,
fixture hashes and clean result records.

## Version 2 symbolic links

New output now uses `FLEXFS2`; validated version 1 snapshots remain importable.
Record offset 12 encodes regular file (0), directory (1), or symbolic link (2).
See [COMPACT-LINUX-SYMLINKS.md](COMPACT-LINUX-SYMLINKS.md) for target validation
and path resolution. Earlier version 1-only readers reject version 2 output.
