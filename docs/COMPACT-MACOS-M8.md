# Compact macOS M8 upstream jq

The reference matrix downloads the unchanged Intel and Apple Silicon
jq 1.8.1 release binaries and verifies their published SHA-256 digests.
On each matching macOS runner it captures exit status, stdout and stderr
for `--version` and the fixed Windows W7 JSON filter and input. It also
records the Mach-O load commands, libraries and undefined symbols.

The hosted audit verifies the source revision, binary, input and inventory
hashes. It runs the exact binaries through the original M6 admission
path. The first boundary is the three-page M6 image cap, 12,288 Intel
bytes and 49,152 ARM64 bytes. Both binaries exceed those fixture limits.

The next gate is `--version` parity in a bounded Mach-O execution profile,
followed by the fixed JSON query under a read-only file grant. The audit
receipt records Ryzova execution as unverified.
