<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase 4.5–4.9 — Reliability and release-candidate engineering

**Scope:** AMD64 experimental kernel. This is infrastructure for release qualification, not a production-release claim. No automatic 9front synchronization, driver implementation changes, kernel binary upload or RyzovaOS distribution.

## 4.5 — Extended bounded reliability / security regression

The native source-built AMD64 QEMU job now runs an additional bounded 256 KiB ramfs write/read-size check, three spawned-and-waited children, and memory-stat sanity check; stage completion requires standalone serial markers and no observed panic lines. The existing Phase 4.1 tests continue to run. Tests reject echoed marker forgery and incomplete writes. This **does not** replace multi-hour soak, fault injection, OOM recovery, DMA isolation, fuzzing, physical SMP testing, or security audit.

## 4.6 — Physical qualification and pre-release evidence

The fail-closed `phase4_release_gate.py` reads the existing driver-agent-owned `ryzova/drivers/physical-tests.json` as read-only input and a draft release manifest. There are currently no qualified physical tests; this remains an explicit blocking condition. Full physical qualification and original log review require access to real equipment and a responsible maintainer. No device coverage is inferred from source IDs.

## 4.7 — Build input provenance / reproducibility

`phase4_provenance.py` records the exact Git commit/tree IDs and pinned 9front builder image digest, and emits a JSON artifact. The existing fresh native build/QEMU pipeline remains the runtime verification source. **Pinning inputs is not a cross-host bit-identical reproducible build demonstration**; independent rebuild and binary comparison remains unverified.

## 4.8 — Community OS variant contract

`phase4_variant_gate.py` checks a minimal sample downstream variant declaration against the experimental-0 SDK contract (AMD64, inherited Plan 9 interfaces, explicit absence of Linux/Windows/macOS binary compatibility). A schema match is not an actual working OS distribution, bootable installer or stable ABI. Community variants need their own userspace and boot test infrastructure.

## 4.9 — Release candidate blocker

`ryzova/release/amd64-preview-candidate.json` is an intentionally incomplete **draft**. CI generates a release-readiness report and asserts that `--enforce-release` blocks publication with exit status 2. Required evidence includes artifact-specific redistribution rights, signed-off source and artifact hashes, independent reproduction, reviewed soak/fuzz evidence, hardware qualification, human approval and signing verification. Even after metadata is supplied, the script **never publishes a binary**; independent review and a human-authorized release process are mandatory.

## CI

- Static lint, unit tests, deterministic provenance report, variant schema validation and release blocker run for pull requests and `main` changes.
- Native source compilation and QEMU second boot run separately via the existing `phase3-native-build.yml`, now including additional Phase 4.5 bounded runtime probes.
- Artifacts are **JSON evidence only**; no kernel binary or firmware is published.
- No code in this phase modifies independent driver-agent branches or re-enables 9front automatic updates.

## Unfinished external gates

Physical driver and machine qualification; license rights-holder/legal sign-off (Issue #3); multi-hour fault-injection and fuzzing; reproducible independent build; security audit; branch protection; stable ABI; signed release authorization. Therefore public binary release is **BLOCKED**.
