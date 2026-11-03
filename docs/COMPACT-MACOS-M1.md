<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Compact macOS — MAC-1 bounded host interpreter research

**Status: experimental, deliberately restricted interpreter for synthetic
Intel x86_64 Mach-O. NOT native Ryzova Kernel guest execution. NOT macOS
application compatibility.**

## What is implemented

The independently written `ryzova/compat/macos/macho_vm.c` integrates
with the hardened MAC-0 `macho64_plan()` metadata parser. It copies accepted
non-PIE `MH_EXECUTE` segment bytes into private, zero-filled virtual memory
with original `initprot` permissions. Source bytes are **never executed by
the Linux/macOS host CPU**; an original bounded AMD64 interpreter decodes
a tiny integer subset and accesses only its own virtual segments.

The initial finite instruction profile:

| AMD64 bytes | Research behavior |
| --- | --- |
| `90` | NOP |
| `B8 id` | MOV EAX, imm32 |
| `05 id` | ADD EAX, imm32, modulo 32 bits |
| `83 C0 ib` | ADD EAX, sign-extended imm8 |
| `31 C0` | XOR EAX,EAX |
| `FF C0` | INC EAX |
| `8B 05 disp32` | MOV EAX, dword ptr [RIP+disp32] (read only) |
| `89 05 disp32` | MOV dword ptr [RIP+disp32],EAX (write only) |
| `EB ib`, `E9 id` | relative jump inside bounded executable, file-backed region |
| `C3` | return to the **synthetic test sentinel** (no real stack/call ABI) |

A real Darwin `LC_MAIN` entry uses a process startup convention,
stack, dyld/libSystem and ABI contracts that this finite test harness
**does not implement**. The `RET` success convention above is explicitly
a research fixture, not macOS process launch.

## Untrusted image and execution budgets

- Maximum input image: 4 MiB.
- Maximum total mapped virtual segment extent: 8 MiB.
- Maximum 16 image segments, each subject to MAC-0 format constraints.
- Execution: at most 4096 interpreted instructions, with stricter
  per-invocation limits allowed; default host probe 128 steps.
- No direct guest access to host pointers; each virtual memory access
  re-checks full-width address range and read/write/execute rights.
- Instruction fetch is only permitted from **file-backed executable**
  bytes; zero-filled BSS is never executed.
- Undefined/unsupported encodings, unsupported control flow, bad address,
  permission violation and infinite loops all fail closed.
- `0F 05` (SYSCALL) is explicitly denied; all unimplemented instructions,
  dyld/mach messaging, Objective-C runtime, filesystem, host network, GUI
  and host syscall forwarding remain forbidden.

`macho_vm_probe.c` is an opt-in **host-side** fixture runner that reads
a local named test file. It is not mounted inside RyzovaOS and cannot
run arbitrary Apple programs. Its output states
`host_interpreter=1 native_guest=0 darwin_syscalls=0`.

## Qualification tests

`tests/test_compact_macos_m1.py` builds the Ryzova C parser and VM with
GCC/Clang and UBSan; it proves synthetic integer code returns 42, bounded
32-bit wrapping, zero-filled mapped memory, memory read/write with segment
permissions, rejection of code writes and data execution, unsupported
syscalls/opcodes, infinite branch budgeting, malformed images and aggregate
memory-size rejection.

Dedicated `.github/workflows/compact-macos-m1.yml` runs these tests on
Linux (GCC/Clang × Python 3.11/3.12) plus macOS host Clang. **Only actual
PASS** results justify marking this MAC-1 research sub-increment verified.
Those tests are **not** source-built native Ryzova guest proof; native
kernel integration and real macOS program acceptance remain MAC-7 goals.

## Future MAC-1 completion gate

A full MAC-1 gate would require a correctly modeled Darwin process entry,
bounded x86_64 ABI state, executable/stack memory separation, accurate
instruction set with differential reference testing, security fuzzing
and an actual QEMU Ryzova guest bridge. None is implied by a passing
synthetic `RET` fixture.

The single draft macOS integration PR remains the only merge vehicle.
No changes to Linux, Windows, drivers or 9front sync are needed for
this incremental, restricted research stage.
