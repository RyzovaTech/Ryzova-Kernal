#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M0.4 independent safety checklist; no hardware is certified by this checker."""
import argparse
import json
import re
from pathlib import Path

from m0_device_registry import RegistryError, read_json, read_firmware

SCHEMA = "ryzova-m0-safety-contract/v1"
NEEDED = ("firmware-provenance", "dma-mapping", "interrupt-quiesce",
          "timeout-recovery", "reset-and-disconnect", "device-power")
MODULE = re.compile(r"[a-z][a-z0-9_]{1,63}\Z")


def audit(contract, firmware, physical):
    """Output only honest blockers, never treat a manifest as physical evidence."""
    if not isinstance(contract, dict) or set(contract) != {
            "schema", "policy", "required_checks", "families"}:
        raise RegistryError("invalid safety contract schema")
    if contract["schema"] != SCHEMA or contract["policy"] != "fail-closed-source-only":
        raise RegistryError("invalid safety contract policy")
    if contract["required_checks"] != list(NEEDED) or not isinstance(contract["families"], list):
        raise RegistryError("required safety checks changed")
    if len(contract["families"]) > 2048:
        raise RegistryError("too many safety families")
    read_firmware(firmware)  # No binary payload, strict manifest format.
    blockers = []
    family_keys = set()
    for entry in contract["families"]:
        if not isinstance(entry, dict) or set(entry) != {"driver", "bus", "checks"}:
            raise RegistryError("malformed family")
        driver, bus, checks = entry["driver"], entry["bus"], entry["checks"]
        if (not isinstance(driver, str) or not MODULE.fullmatch(driver) or
                bus not in ("pci", "usb") or (bus, driver) in family_keys):
            raise RegistryError("invalid/duplicate safety family")
        family_keys.add((bus, driver))
        if not isinstance(checks, dict) or set(checks) != set(NEEDED):
            raise RegistryError("missing safety checks for " + driver)
        for key in NEEDED:
            if checks[key] not in ("unverified", "source-audited"):
                raise RegistryError("unattested safety promotion: " + driver + ":" + key)
            blockers.append({"driver": driver, "check": key, "status": checks[key],
                             "reason": "no-physical-validation"})
    if physical.get("schema") != "ryzova-physical-driver-tests/v1":
        raise RegistryError("physical test schema mismatch")
    records = physical.get("test_records")
    if not isinstance(records, list):
        raise RegistryError("invalid physical records")
    # Existing D-series release gate validates rich test evidence separately.
    # We are incapable of attesting an operator's hardware from a JSON file.
    # Refuse promotion even if someone injects records or 'approved' fields.
    reasons = ["manual-hardware-safety-and-rights-approval-required"]
    if not records:
        reasons.append("no-physical-hardware-test-records")
    if firmware["entries"]:
        unresolved = [f["id"] for f in firmware["entries"]
                      if f["redistribution"] != "cleared-by-human-review" or f["sha256"] is None]
        if unresolved:
            reasons.append("firmware-rights-or-hash-not-cleared")
    return {
        "schema": "ryzova-m0-safety-gate/v1",
        "gate": "blocked",
        "auto_release_allowed": False,
        "family_count": len(family_keys),
        "unverified_contract_checks": len(blockers),
        "check_blockers": blockers,
        "release_blockers": reasons,
        "physical_test_records_present_not_attested": len(records),
        "message": "Source checks do not validate DMA, IOMMU, IRQ, firmware rights, or physical operation."
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    root = args.root.resolve()
    try:
        out = audit(
            read_json(root / "ryzova/drivers/m0-safety-contract.json"),
            read_json(root / "ryzova/drivers/m0-firmware-manifest.json"),
            read_json(root / "ryzova/drivers/physical-tests.json"))
    except (OSError, ValueError, RegistryError) as exc:
        p.exit(1, "M0 safety check rejected: " + str(exc) + "\n")
    data = json.dumps(out, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
