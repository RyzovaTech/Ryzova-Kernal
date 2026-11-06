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

The separate M8 loader maps both pinned images in a bounded guest address
range. Its hosted check verifies the entry address, zero-initialized data,
guest segment permissions, and chained rebases and binds. Binds use
unresolved guest tokens. The check also rejects malformed images without
changing the arena or the output plan.

| Image | Mapped bytes | Rebases | Binds |
| --- | ---: | ---: | ---: |
| Intel | 856064 | 1221 | 136 |
| ARM64 | 851968 | 1232 | 135 |

The hosted startup check passes `jq --version` arguments into each guest
entry point. Intel uses the existing AMD64 instruction engine with
Windows API dispatch and bootstrap handling disabled. ARM64 runs a
bounded instruction subset. Both stop at the unresolved `_setlocale`
call, after 15 Intel instructions and 18 ARM64 instructions. Each path
also rejects an invalid entry opcode before reaching a guest import.

Darwin import implementations and instruction coverage for the remainder
of the workload are pending. The execution gates are `--version` parity
and the fixed JSON query under a read-only file grant on a source-built
Ryzova guest.
