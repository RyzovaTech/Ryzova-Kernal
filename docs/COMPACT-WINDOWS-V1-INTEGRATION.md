# Compact Windows W1–W6 — one-time main integration

This **opt-in, bounded** AMD64/PE32+ Windows compatibility subset is fully
contained in the W1–W6 branch and has 31 preceding source commits. This
single PR integrates the branch into `main` once, rather than merging its
original draft W1→W6 stacked PRs individually. It introduces new Windows
files, original host/native Plan 9 portability implementations, frozen MSVC
test fixtures, and independent CI workflows. It does **not** modify driver
agents, `ryzova/compat/linux`, upstream 9front synchronization, or preexisting
kernel source.

The source-built native AMD64/QEMU W6 profile has 22 cases. It verifies
Win32 PE console/CRT subset, namespace rights, fixed process and I/O budgets,
a real dedicated 9P/virtio-SCSI storage barrier, exact W4 two-flush ACKs,
fresh boot file-SHA recovery after QEMU SIGKILL, and injected write/cache
failure and sticky-uncertainty denial (error 1117 / zero ACKs).
Full evidence and generated independent acceptance JSON:
https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41304810910

The new `compact-windows-main-integration.yml` additionally guards the
exact main-targeted PR and rejects non-Windows source changes and falsely
qualified release status. Existing W1→W6 and inherited main CI must pass
against the new base before the authorized one-time merge.

**Nonclaims / later phases:** Hardware/firmware power-cut and post-ACK physical
disk durability are untested; ordinary boot hjfs is not crash safe under
QEMU SIGKILL; ARM64 Windows, x86 WoW64, GUI, DirectX, .NET, registry, COM,
generic arbitrary apps and broad hardware drivers are excluded. These are
not silently waived on merge. The seven formal Windows V1 release gates
remain pending, `full_w6_complete=false`, and the project must not publish
this merged subset as general Windows compatibility.

This is a **feature integration**, not a final OS release or physical-device
certification. Repository/driver-agent ownership remains separate.
