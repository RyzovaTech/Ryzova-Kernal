<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 5.6 — Host-only compatibility security regressions

The tests on the Phase 5 draft branch exercise an untrusted-binary parser boundary and a virtual-namespace path policy. They use deterministic input mutation, strict GCC and Clang builds, UndefinedBehaviorSanitizer and explicit negative-case checks.

- 100 mutated ELF64 inputs (including truncation), 100 mutated Windows PE32+ inputs, and 100 mutated macOS Mach-O x86_64 inputs.
- 10,000 deterministic randomly generated namespace paths verified against allowed success/error categories; no file-system passthrough.
- Repeat the Phase 5.4 bounded virtual Linux interpreter negative tests (invalid opcode, unknown syscall, instruction budget and corrupt ELF).
- Mutation testing is a bounded smoke security check, **not** exhaustive fuzzing or a formal security audit. No claim of arbitrary ELF safety, user/kernel privilege protection, protected memory execution, or successful exploitation resistance.
- Host CI tests **do not** run foreign binaries in a native Ryzova Kernel process. Real Ryzova guest syscall/trap integration is still an unsatisfied gate.

No production kernel source, third-party driver or 9front upstream sync workflow is modified by this phase.
