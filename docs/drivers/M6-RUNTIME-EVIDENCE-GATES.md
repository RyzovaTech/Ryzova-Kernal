<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Phase M6 — ARM64 Runtime Evidence Gates

**Status: source-level evidence contract only. No ARM64 guest functional I/O, physical device, DMA/IOMMU isolation, or production server certification is claimed.**

This document complements draft PR #51's M6 runtime qualification plan. It does not modify PR #49's ARM64 native bootstrap, 9front sync settings, driver-agent-owned code, Phase 7 TLS or Phase 8 security code.

## Evidence dependencies

M6 observations are considered in strict order, always matched to the exact source HEAD:

1. Native ARM64 \`7c\` compilation of M5 ECAM and PCI modules.
2. Verified target ARM64 \`paqfs\` and \`factotum\` plus \`9qemu\` link.
3. M5 QEMU probe report \`ryzova-m5-arm64-native-qemu/v1\` with independently compared uImage SHA-256 and observed boot output.
4. **Future** host/guest runtime report \`ryzova-m6-arm64-guest-runtime/v1\` containing matched bidirectional VirtIO network hashes and positive packet counts, VirtIO block guest write/readback/host flush hashes, multicore IRQ recovery, and DMA bounds/teardown negatives.
5. Separate independent physical lab review, owner-approved qualified models and explicit human release. Neither a serial transcript nor self-reported JSON can satisfy this last step.

M6.2–M6.3 test fixture JSON is synthetic and validates the parser **only**. A passing unit test never means that VirtIO, SMP, GIC, DMA or IOMMU have run on ARM64 QEMU.

## Run the gate

\`\`\`sh
python3 scripts/m6_runtime_evidence.py \
  --cross artifacts/phase3/m5-arm64-native-build.json \
  --boot artifacts/phase3/m5-arm64-qemu-probe.json \
  --runtime artifacts/m6/arm64-guest-runtime.json \
  --expected-head "$(git rev-parse HEAD)" \
  --output artifacts/m6/runtime-evidence.json
\`\`\`

Any absent report leaves dependent checks false, and an absent ARM64 runtime report cannot become a success merely from AMD64 QEMU boot or ARM64 compilation. The optional \`--enforce-runtime\` exits nonzero unless all observational checks are consistent. Even when consistent, data is **unattested**, \`hardware_release_ready\` stays false and \`newly_certified_physical_models\` stays zero.

## Next live test integration

After PR #49 actually produces a linked, SHA-checked ARM64 uImage and fresh AArch64 QEMU boot, create a dedicated guest test runner that emits the runtime schema from captured QEMU host/guest evidence, not from manually edited JSON. Verify:

- VirtIO-net packets both directions, with host and guest independent SHA-256 over real payload.
- VirtIO-blk actual guest write/read/flush, host-backed disk digest check and reboot recovery.
- SMP/GIC/IRQ registration races, storms and device removal.
- DMA bounds, mapping failure, teardown and emulated IOMMU. Do **not** infer physical SMMU isolation.
- Preserve all fresh source-built AMD64 QEMU network/storage/9P, server and legacy PC regressions.
- Rebase and verify exact-head workflows after concurrent main merges.

No automatic 9front sync, automatic cross-architecture device binding, vendor firmware redistribution, or speculative claim of one million qualified hardware devices is introduced.
