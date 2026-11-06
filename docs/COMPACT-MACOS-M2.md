<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Compact macOS — MAC-2A capture-only Darwin BSD syscall research

**Status: original host-side isolated syscall simulation. Not a Darwin
kernel, real Mach IPC, macOS application execution or native Ryzova guest.**

## Exact scope

The original MAC-1 virtual Mach-O CPU keeps its default deny-all-syscalls
behavior (`ryz_mac1_run`). An **explicitly separate** API
`ryz_mac2_run` accepts only two Darwin x86_64 BSD-class syscall numbers:

| Darwin x86_64 number | MAC-2A action |
| --- | --- |
| `0x02000004` | Bounded `write(fd=1, guest_ptr, length)` into a private **256-byte** result buffer |
| `0x02000001` | Simulated `exit(status)`, records the low 8 bits of status; never exits host process |
| Any other syscall or class | Explicit `RYZ_MAC1_SYSCALL_DENIED`, no host forwarding |

The numbers use the original Darwin/XNU BSD-class prefix (`0x02000000`),
not Linux x86_64 syscall numbers. This finite proof-of-concept uses
`EAX` for the syscall ID, `RDI` for file descriptor or exit status,
`RSI` for the virtual guest address and `RDX` for the write length.
Only a small supporting instruction subset (`MOV EDI/EDX,imm32`,
`LEA RSI,[RIP+disp32]`, `XOR EDI,EDI`) is added to the interpreter.

The write service **never** calls host `write`, `open`, `connect`,
`send`, file APIs or the Mach trap interface. Guest pointer access must
be within one readable, bounded, already-validated virtual segment.
Oversized writes, output accumulation above 256 bytes, invalid read
ranges and wrong descriptors fail closed. The opt-in research probe prints
only hex-encoded evidence and explicitly marks `native_guest=0` and
`host_syscall_forwarding=0`.

The opt-in service **is not compatible with libSystem** and is not
designed for arbitrary macOS executables. `dyld`, true Darwin
error/carry-flag propagation, `RAX/RCX/R11` clobber behavior, Mach IPC,
thread creation, Unix file descriptors, terminal access, signal delivery
and sandboxed native Ryzova guest execution are **OPEN**.

## Acceptance evidence

- `tests/test_compact_macos_m2.py`: simulated bounded "Hello from
  Ryzova" `write` + `exit`; no host payload forwarding; default MAC-1
  still rejects syscalls; unknown BSD/Mach class, wrong FD,
  invalid pointer, overlimit output, and no-return-without-exit denial.
- `.github/workflows/compact-macos-m2.yml`: Clang host compilation,
  UBSan, tests on macOS and Linux, plus inherited MAC-0/1 regressions.
- MAC-2A passing synthetic host tests does **not** close MAC-2 or MAC-6.
  Actual application execution, compatibility and fault isolation must
  be proven on native Ryzova in later phases. The only merge vehicle
  remains Draft PR #90 with exact-head gating.

Format/numbering references:
- Apple XNU open-source syscall class definitions, `osfmk/mach/syscall_sw.h`.
- Apple/XNU BSD `syscalls.master` numbers for `exit` and `write`.

## Reproducible Clang-generated Darwin-host-only demonstration

Run `python3 scripts/compact_macos_m2_demo.py` on a developer machine
with Clang and a C compiler. It assembles a real relocation-free x86_64
Darwin `MH_OBJECT` from original source, extracts its bounded text
bytes, wraps them in a **synthetic static Mach-O test image**, builds
the host-only C interpreter, and verifies that simulated Darwin
`write(1,...)` captured exactly `Hello from Ryzova\\n`.
The output is a JSON evidence record with explicitly **false** native
Ryzova guest and linked macOS application verification fields.
This is **not** installing, launching or linking a macOS application.
