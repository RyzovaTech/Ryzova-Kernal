<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D0.2 — AMD64 PCI probe evidence & firmware dependencies

**Scope:** driver inspection automation, no hardware claims.

This is a **source-level evidence map**, not a device support database and not a
release qualification. It indexes a small bounded set of 15 *enabled* AMD64
driver modules. Additional modules require separate probe-path review.

## Procedure

From a checkout that includes D0.1:

```sh
python3 -m unittest discover -s tests -p 'test_driver_inventory.py' -v
python3 -m unittest discover -s tests -p 'test_hardware_evidence.py' -v
python3 scripts/hardware_evidence.py --output artifacts/drivers/d0-2-hardware-evidence.json
```

The GitHub CI workflow uploads the generated JSON as a 30-day review artifact.

## Evidence types

- **Exact literal probe**: a literal `pcimatch(..., vendor, device)`; even this
  only shows a source-level probe, not complete hardware initialization.
- **Vendor-only scan**: `pcimatch(..., vendor, 0)` enumerates devices from a
  vendor, but does *not* mean every vendor device is accepted.
- **Vendor-scoped switch candidate**: a literal device-ID case near a
  vendor-specific `pcimatch` scan. This is a conservative static heuristic;
  a human still must inspect predicates and runtime error paths.
- **PCI class selector**: NVMe, xHCI, HDA and conditional AHCI matching use
  class code conditions; these cannot be counted as a finite list of models.
- **Runtime firmware reference**: the driver references a path/name. Firmware
  packages and their redistribution rights remain unreviewed; generated
  results do not include firmware binaries.

Sources show, for example, Intel i225/i226 ID cases in
[`etheri225.c`](../../sys/src/9/pc/etheri225.c), VirtIO and storage probes,
and Intel Wi-Fi firmware names in
[`etheriwl.c`](../../sys/src/9/port/etheriwl.c).

## Audit limits and false-positive guardrails

1. Extracted probe candidates are not verified supported PCI IDs. Vendor
   selection, device revisions, BAR layouts and firmware may reject a match.
2. Class-based matching can potentially reach numerous devices, but has
   no verifiable total without a hardware compatibility laboratory.
3. A `/lib/firmware` string is not evidence that a usable firmware file
   exists or can legally be redistributed.
4. Dynamic arithmetic expressions, symbolic device IDs, packed tables,
   complex vendor guards, alternate USB ID tables and other probe structures
   are not fully resolved. Missing entries do not prove lack of support.
5. Comments are ignored when extracting PCI matches. A source file is
   necessary evidence, never sufficient for hardware certification.
6. The JSON includes `physical_hardware_status=unverified` for every driver.
   QEMU smoke tests from earlier phases cannot certify real hardware.

## Next handoff

- D0.3: human review of selected source candidates and vendor/device tables;
  add symbolic/packed-ID decoding, USB handling and explicit firmware/license
  records without changing the runtime drivers.
- D2: isolated VirtIO network/block regression and error-path tests.
- Real-device qualification requires a logged PCI ID + revision + firmware
  version + source SHA, observed runtime and reproducible failure tests.

**Dependencies:** D0.1 PR #13 provides the common configuration parser.
This PR is deliberately stacked on that branch and must not be merged ahead
of the D0.1 dependency without rebasing.

No 9front automatic synchronization, binaries or unrelated kernel changes.
