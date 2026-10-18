#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M0.5 evidence-gap report for separate modern and legacy AMD64 tracks.

Never infers physical support from inventory, CI, synthetic fixtures, or
self-entered JSON. Existing D-series human release gate is authoritative.
"""
import argparse
import json
from pathlib import Path

from m0_device_registry import RegistryError, read_json

SCHEMA = "ryzova-m0-qualification-plan/v1"
REQUIRED_TRACKS = ("modern-amd64", "legacy-amd64")
REQUIRED_TESTS = ("boot", "io-integrity", "error-recovery", "stress")


def evaluate(plan, physical):
    if not isinstance(plan, dict) or set(plan) != {"schema", "release_policy", "platforms"}:
        raise RegistryError("invalid qualification plan")
    if plan["schema"] != SCHEMA or plan["release_policy"] != "human-evidence-required":
        raise RegistryError("unsafe qualification policy")
    if not isinstance(plan["platforms"], list) or len(plan["platforms"]) != 2:
        raise RegistryError("both Modern/Legacy tracks required")
    if not isinstance(physical, dict) or physical.get("schema") != "ryzova-physical-driver-tests/v1":
        raise RegistryError("invalid physical evidence schema")
    if not isinstance(physical.get("test_records"), list):
        raise RegistryError("physical test records must be a list")
    platforms = []
    for i, row in enumerate(plan["platforms"]):
        fields = {"id", "profile", "description", "min_physical_devices",
                  "mandatory_tests", "additional_tests", "qualified"}
        if not isinstance(row, dict) or set(row) != fields:
            raise RegistryError("invalid track fields")
        if row["id"] != REQUIRED_TRACKS[i]:
            raise RegistryError("modern and legacy tracks cannot be removed or reordered")
        if row["mandatory_tests"] != list(REQUIRED_TESTS):
            raise RegistryError("missing mandatory test")
        if (type(row["min_physical_devices"]) is not int or
                row["min_physical_devices"] < 2 or
                row["min_physical_devices"] > 100):
            raise RegistryError("invalid minimum physical device coverage")
        if row["qualified"] is not False:
            raise RegistryError("cannot assert unsupported qualification")
        if not isinstance(row["profile"], str) or not row["profile"].strip():
            raise RegistryError("missing track profile")
        if (not isinstance(row["additional_tests"], list) or
                len(row["additional_tests"]) < 4 or
                any(not isinstance(x, str) or not x for x in row["additional_tests"]) or
                len(set(row["additional_tests"])) != len(row["additional_tests"])):
            raise RegistryError("missing or duplicated extended test cases")
        platforms.append({
            "id": row["id"],
            "qualification": "blocked",
            "required_physical_devices": row["min_physical_devices"],
            "attested_physical_devices": 0,
            "hardware_evidence": "not-reviewed",
            "mandatory_tests": row["mandatory_tests"],
            "additional_tests": row["additional_tests"],
            "blockers": ["physical-test-evidence-not-independently-verified",
                         "human-release-authorization-required"],
        })
    return {
        "schema": "ryzova-m0-qualification-report/v1",
        "overall": "blocked",
        "certified_hardware_models": 0,
        "claims_not_certified": len(physical["test_records"]),
        "platforms": platforms,
        "source_data_cannot_self_certify": True,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    root = args.root.resolve()
    try:
        report = evaluate(
            read_json(root / "ryzova/drivers/m0-qualification-plan.json"),
            read_json(root / "ryzova/drivers/physical-tests.json"))
    except (RegistryError, OSError, ValueError) as e:
        p.exit(1, "M0 qualification rejected: " + str(e) + "\n")
    result = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
