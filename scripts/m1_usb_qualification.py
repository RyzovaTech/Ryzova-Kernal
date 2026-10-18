#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M1 USB source candidate / real-device qualification gap report."""
import json
from pathlib import Path
import sys
from m0_device_registry import CandidateIndex, RegistryError, read_json

BASE = Path(__file__).resolve().parents[1]


def evaluate(plan, registry, firmware, root):
    if (not isinstance(plan, dict) or set(plan) !=
            {"schema", "policy", "platforms", "classes"} or
            plan["schema"] != "ryzova-m1-usb-qualification/v1" or
            plan["policy"] != "no-source-only-certification" or
            plan["platforms"] != ["modern-amd64", "legacy-amd64"]):
        raise RegistryError("unsafe M1 qualification plan")
    index = CandidateIndex(registry, firmware, root)
    index.verify_pc64_configuration(root)
    mapping = {r["id"]: r for r in registry["rules"]}
    expected = {
        "usb-hid": "kb", "usb-mass-storage": "disk",
        "usb-audio": "audio", "usb-cdc-ethernet": "ether",
    }
    blockers = []
    if not isinstance(plan["classes"], list) or len(plan["classes"]) != len(expected):
        raise RegistryError("all four universal USB class families required")
    seen = set()
    for row in plan["classes"]:
        if not isinstance(row, dict) or set(row) != {
                "id", "driver", "selectors", "required_tests", "certified"}:
            raise RegistryError("invalid M1 class entry")
        name = row["id"]
        if name not in expected or name in seen or row["driver"] != expected[name]:
            raise RegistryError("unexpected/duplicate M1 class")
        seen.add(name)
        if row["certified"] is not False:
            raise RegistryError("M1 certification requires independent physical evidence")
        tests = row["required_tests"]
        if (not isinstance(tests, list) or len(tests) < 5 or
                "native-build" not in tests or len(tests) != len(set(tests)) or
                any(not isinstance(t, str) or not t for t in tests)):
            raise RegistryError("missing M1 class qualification tests")
        selectors = row["selectors"]
        if not isinstance(selectors, list) or not selectors or len(set(selectors)) != len(selectors):
            raise RegistryError("invalid class selectors")
        for rid in selectors:
            if rid not in mapping:
                raise RegistryError("unregistered M1 USB selector " + rid)
            source = mapping[rid]
            if source["bus"] != "usb" or source["driver"] != row["driver"] or source["binding_enabled"] is not False or source["evidence_level"] != "source-candidate":
                raise RegistryError("unsafe candidate or wrong driver family " + rid)
        blockers.append({"class": name, "status": "not-certified",
                         "required_tests": tests,
                         "modern_and_legacy_hardware": "not-independently-attested"})
    return {"schema": "ryzova-m1-usb-gate/v1", "status": "blocked",
            "certified_models": 0, "class_source_candidates": sum(
                len(x["selectors"]) for x in plan["classes"]),
            "platforms": plan["platforms"], "classes": blockers,
            "auto_bind_allowed": False}


def main():
    root = BASE
    try:
        result = evaluate(read_json(root/"ryzova/drivers/m1-usb-qualification.json"),
                          read_json(root/"ryzova/drivers/m0-device-registry.json"),
                          read_json(root/"ryzova/drivers/m0-firmware-manifest.json"), root)
    except (ValueError, OSError, RegistryError) as exc:
        sys.exit("M1 qualification rejected: " + str(exc))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
