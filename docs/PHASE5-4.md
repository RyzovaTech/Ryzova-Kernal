<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.4 — Real Linux ELF static application, bounded **host interpreter** PoC

**Verified scope is an offline instruction interpreter on a Linux GitHub CI host, NOT native Ryzova Kernel application execution inside QEMU.** Native Ryzova/9front kernel loader and trap path remain unmodified.

The test compiles a genuine static Linux x86-64 ET_EXEC from .S and does **not** cheat by running the guest with `execve` or forwarding its Linux syscalls to the host. Our `subset_vm.c` checks the ELF load plan from Phase 5.1, materializes all PT_LOAD segments into a strictly bounded buffer, fetches instructions only from file-backed executable segments, and interprets a deliberately tiny instruction set: `mov r32, imm32` (zero-extended), `lea disp32(%rip), %rsi`, `xor %edi,%edi`, `nop`, `jmp rel8` and `syscall`.

The `syscall` instruction is **not a host syscall**: it calls the previously written Phase 5.2 virtual Linux syscall engine, allowing only `write(1)`, `exit(60)`, and `exit_group(231)`, using the Phase 5.3 isolated guest process namespace and a controlled host **output callback only**. There is a 2 MiB contiguous guest arena cap and 2,048-step budget. No RWX executable native pages are allocated and no ELF instruction bytes jump into the real CPU via native execution.

GCC and Clang CI verifies: real ELF prints `RYZOVA_LINUX_HELLO` and exits through our interpreted syscall path; comparison against native host reference output (reference only), bad opcode, unsupported syscall, infinite loop and corrupted ELF rejection. UndefinedBehaviorSanitizer and freestanding compile checks included.

**Still necessary before claiming Ryzova Kernel runs Linux apps:** port into native Plan 9 build, define safe executable memory mapping and trap dispatch, real user-mode register state and stack/auxv, ABI error translation in the kernel, kernel-side kernel/guest privilege separation, and fresh kernel QEMU execution evidence. The existing QEMU native-build CI only confirms the baseline kernel still boots; it does not exercise this host-only PoC. The interpreter supports only the exact synthetic assembly idiom tested; general static Linux programs, glibc and dynamic ELF remain unsupported.
