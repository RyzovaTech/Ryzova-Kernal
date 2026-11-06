# Compact macOS M9.3 SQLite execution

Both unchanged SQLite 3.54.1 release binaries are exercised through
`--run`. The hosted gate compares the exact macOS outputs for
`--version` and the in-memory `SELECT 6*7;` workload. It also evaluates
`SELECT 7*8;` to verify that the guest executes the caller's SQL.

The native job rebuilds the Ryzova kernel and launcher with the guest
toolchain, verifies their digests after reboot, and compares each
stdout and stderr digest and the successful exit with macOS.

The profile has one guest thread and uses private mutex and allocation
state. It exposes a virtual `/dev/null` for SQLite's empty init file,
one virtual CPU and a fixed guest clock. Files and entropy devices from
the host namespace are unavailable through the POSIX descriptor API.
The tested SQL workload uses an in-memory database. Persistent SQLite
files, extension loading and general SQLite compatibility are outside
this qualification.
