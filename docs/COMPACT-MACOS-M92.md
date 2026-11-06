# Compact macOS M9.2 SQLite admission

The second CLI is the upstream SQLite 3.54.1 shell. CI verifies the
published SHA3-256 for each official macOS ZIP and pins the SHA-256 of
the unchanged `sqlite3` member. Matching macOS runners capture
`--version` and an in-memory `SELECT 6*7;` query.

| Guest architecture | File bytes | Mapped bytes | Binds | Rebases |
| --- | ---: | ---: | ---: | ---: |
| Intel | 2136544 | 2136544 | 196 | 2680 |
| ARM64 | 2069752 | 2097152 | 196 | 2774 |

The loader accepts a bounded 4 MiB image while keeping the read-only
file capability capped at 1 MiB. It checks the final read-only link
segment, zeroes the trailing writable BSS and common storage, and walks
the bounded fixup-page prefix. The ARM64 unwind metadata is mapped as
file bytes. The exact rpath is accepted as metadata. It does not
participate in library lookup.

The import table distinguishes libSystem from libz. Only libSystem
entries are eligible for the existing guest service resolver. Both
images have 12 libz imports, which retain inert guest tokens. CI checks
every fixup value, executable entry permissions, BSS contents, and
rejection of malformed mappings. M9.3 covers actual SQLite execution and
output parity in the source-built Ryzova QEMU guest.
