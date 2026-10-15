<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Ryzova Kernel Driver Series (D0–D6) — engineering gates

This is an engineering record for the independent **AMD64 Ryzova Kernel**,
not a statement that all hardware families or driver stages are complete.

## Phase status and evidence

| Stage | Scope | Current technical result | Remaining gate |
|---|---|---|---|
| D0 / D0.1 | Existing driver audit and deterministic configuration inventory | Audit PR #12; parser + CI PR #13 | Review and merge, then broaden audit |
| D0.2 / D0.3 | PCI source probe and firmware dependency inventory | Source scanner PR #16; source matrix and collision report here | Validate symbolic/packed IDs, USB VID/PID, firmware legal provenance |
| D1 | Safe driver engineering workflow | Deterministic JSON, parser tests and provenance-aware reports | Approve stable interface/driver development standards |
| D2 | Essential drivers: storage, network, USB, input | Existing drivers present; prior QEMU VirtIO network smoke documented | Expanded fault/transfer tests and real hardware |
| D3 | Modern PCs: Wi-Fi, HDA, laptop power/display | Source present for selected families | Controller/revision, firmware, suspend/resume and laptop lab testing |
| D4 | Advanced GPU/Bluetooth/accelerators | NOT verified | Separate research, code development and physical qualification |
| D5 | Driver stability, performance, security | Deterministic source checks and CI regression tests available | Fuzzing, DMA/error-path, sustained I/O and measured benchmarks |
| D6 | Release qualification | Fail-closed machine report and physical-evidence schema implemented | Maintainer review, legal clearance, physical device logs and approval |

**None of D2-D6 are qualified as complete** without device-level testing and
authorized sign-off. CI success for a source audit never implies that a real
motherboard, Wi-Fi card or GPU is working.

## Run the safe static pipeline

```sh
python3 -m unittest discover -s tests -p 'test_driver_inventory.py' -v
python3 -m unittest discover -s tests -p 'test_hardware_evidence.py' -v
python3 -m unittest discover -s tests -p 'test_packed_pci_evidence.py' -v
python3 -m unittest discover -s tests -p 'test_driver_release_matrix.py' -v
python3 scripts/driver_release_matrix.py \
  --output artifacts/drivers/d-series-matrix.json \
  --gate-output artifacts/drivers/d-series-release-gate.json
```

The D0.3 packed-ID extractor additionally resolves reviewed Realtek RTL8169
and Intel igbe probe-switch cases written as `(did<<16)|vid`. This still
cannot certify any physical device and does not cover arbitrary C expressions.

The matrix lists distinct source candidates, PCI class patterns, possible
conflicts, and firmware name/path references. **Not all IDs are decoded.**
No firmware binary is downloaded, bundled or relicensed.

To explicitly validate that production distribution is **not authorized**, run:

```sh
python3 scripts/driver_release_matrix.py --enforce-release
```

This returns a nonzero status by design until an independent release
authorization workflow exists. It is not acceptable to change this to
'green' simply to make CI pass.

## Physical test evidence contract

The source-backed file `ryzova/drivers/physical-tests.json` is **empty**.
Future physical lab records require device vendor/device ID, revision,
tested kernel commit SHA, firmware version, dated operator identity,
cryptographic log digest and pass results for boot, IO integrity, recovery and
stress testing. Records cannot be validated purely by schema: human review
and original evidence remain mandatory. The strict gate will always require
a separate authorized maintainer action and explicit third-party license
clearance; it never publishes a kernel binary.

## Independence and scope

- 9front automatic upstream source syncing remains disabled.
- AMD64 driver-only scope; kernel scheduler, memory manager, general ABI,
  RyzovaOS and blanket license changes are out of scope.
- No GPL source code, firmware blobs, executables or binaries are imported.
- For each new driver: record chipset revision, specification, source
  provenance, tests, firmware terms and reproducible bench/failure logs.
- Driver CI must avoid storing passwords, sensitive serial numbers or
  personally identifying host inventory in public artifacts.
- D0.1 PR #13 and D0.2 PR #16 are currently draft dependencies.
