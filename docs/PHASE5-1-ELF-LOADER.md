<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.1 — Linux AMD64 ELF64 load-plan foundation

Files: [elf64.c](../ryzova/compat/linux/elf64.c), [elf64.h](../ryzova/compat/linux/elf64.h), [elf64_probe.c](../ryzova/compat/linux/elf64_probe.c).

## Supported now
- Parse **ELF64 little-endian, x86-64, ET_EXEC only** from caller-supplied bounded image bytes.
- Validate ELF magic/version, OSABI (System V/Linux), program-header count and file range.
- Inspect up to 32 program headers and 16 non-overlapping page-aligned PT_LOAD ranges.
- Check file-backed length, zero-filled BSS, mapped-virtual-memory budget (64 MiB), lower-half user virtual-address range (minimum 0x10000), segment alignment and non-writable executable mappings.
- Confirm entrypoint lies in **file-backed executable bytes**.
- Reject PT_INTERP, PT_DYNAMIC, PT_TLS, executable GNU_STACK, unsupported ET_DYN/PIE, W+X, overlapping map pages, corrupt lengths and integer overflow.
- Return deterministic `RyzElf64Plan` segment metadata, or copy one segment's file bytes into a caller-owned destination and zero-fill remaining BSS. No allocation in the parsing library, and no program execution.
- A host-only `elf64_probe` exercises this library against synthetic hostile ELF headers and a truly compiled static x86-64 Linux ELF (validated, **not executed**).

## Running the tests
```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 \
  ryzova/compat/linux/elf64.c ryzova/compat/linux/elf64_probe.c -o elf64_probe
python3 -m unittest discover -s tests -p test_phase5_elf.py -v
```
The GitHub `phase5-elf.yml` workflow tests with GCC and Clang, compiles real static ET_EXEC fixture without glibc, and archives non-binary test reports only.

## Explicitly NOT supported
No ET_DYN/PIE, dynamic loader or .so resolution, TLS, relocations, Linux system call emulation, process stack construction, signal handling, shared memory, file descriptors, filesystem translation, or process launch. The returned load-plan **is not yet connected to Ryzova's native Plan 9 process address-space manager**. This step must be reviewed in Phase 5.2; do not treat successful host tests as native QEMU application execution.

## Acceptance criteria
1. Strict compiler warnings-as-errors builds pass.
2. A genuine static Linux AMD64 ET_EXEC is parsed and materialized *without executing code*.
3. Malformed ELF/overflow/unsafe memory layout inputs fail closed, including forged entrypoints and executable stack.
4. Existing native kernel build and QEMU regressions remain green on this branch.
5. No merge to main until all Phase 5 stages finish and user authorizes it.
