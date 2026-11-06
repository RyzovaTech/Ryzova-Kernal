# Compact macOS M9 launcher

The native launcher accepts the guest argument vector and an optional
read-only file capability.

```sh
compact-macos-m8 --run /path/to/jq -- jq --version
compact-macos-m8 --run --read-only records.json /work/input.json /path/to/jq -- jq -c '.items' records.json
```

The launcher opens the host file with read-only access and gives the runtime
an immutable snapshot. The guest opens the exact alias. A name is at most 63
ASCII letters, digits, periods, underscores or hyphens. Dot and dot-dot are
reserved. The runtime denies traversal, absolute paths and ungranted names.
The original M8 commands and fixed `input.json` API retain their behavior.

The first M9 gate runs the same pinned Intel and ARM64 jq binaries with a
caller-selected argument vector and file alias. Hosted tests check alternate
arguments, bad aliases and access denial. The native gate checks M8 reference
parity through `--run` on the source-built Ryzova guest.

Qualification of a second unchanged upstream CLI is the remaining M9 gate.
