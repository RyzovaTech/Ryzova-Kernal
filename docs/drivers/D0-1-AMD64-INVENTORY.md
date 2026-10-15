<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D0.1 — AMD64 configuration inventory (experimental)

This driver-track deliverable converts the **existing** 9front-derived AMD64
`sys/src/9/pc64/pc64` configuration into deterministic, machine-readable JSON.
It **does not install, fix, write or qualify any driver**.

## Run locally

```sh
python3 -m unittest discover -s tests -p 'test_driver_inventory.py' -v
python3 scripts/driver_inventory.py --output artifacts/drivers/amd64-pc64.json
```

The parser requires Python 3.9+ and uses only the standard library. The
separate `driver-inventory.yml` GitHub Action runs the tests and uploads
the generated JSON as a review artifact for every relevant PR or manual run.
The manifest is generated from the checked-out source at CI runtime, not from
a moving 9front upstream repository. It does not modify `main`.

## Scope of the generated JSON

Every entry records the configuration section, line number, module name,
enabled/disabled flag, tokens after the module name, broad component family,
and whether a direct C source filename exists under the supported kernel
source directories. The file SHA-256 allows the reviewer to identify the exact
configuration that was parsed. Entries retain their source order.

**Deliberate unknowns:** supported PCI/USB IDs, firmware licenses and
distribution rights, test evidence and physical hardware qualification are
`not-reviewed` or `unverified` until a human reviews the relevant driver
and hardware documentation. A configured, source-present module is *not*
a verified device. `dev`, `link`, `misc` and `ip` sections are indexed;
`port` and `bootdir` are not hardware driver inventories.

This first-pass parser recognizes commented-out entries by known module-name
prefixes to exclude ordinary prose comments. If additional 9front config
conventions are found, update fixtures and implementation together.

## Next controlled steps

1. Review manifest entries and map genuine PCI/USB probe tables to specific
   source locations without claiming unsupported IDs.
2. Produce a maintainer-approved device-ID and firmware provenance matrix.
3. Select one existing VirtIO target for targeted error-path/functional tests,
   then propose code changes in a separate driver-specific PR.
4. Require independent QEMU and **physical** hardware verification before
   labelling real-device support release-qualified.

No upstream sync, kernel ABI, scheduler, memory manager or non-driver code
changes are part of this track. See [D0 audit draft PR #12](https://github.com/RyzovaTech/Ryzova-Kernal/pull/12).
