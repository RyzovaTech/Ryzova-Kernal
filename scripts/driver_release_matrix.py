#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build source-level AMD64 device/firmware matrix and fail-closed release report.

No runtime driver or hardware is exercised by this script. In particular:
- class-code matches are not a finite device-ID list;
- PCI ID candidates are NOT proof of device support;
- firmware *names* do not imply firmware exists or may be distributed.
"""
import argparse
import json
import re
from pathlib import Path

from hardware_evidence import build as source_evidence
from packed_pci_evidence import packed_pci_candidates

HEX4 = re.compile(r"^[0-9a-fA-F]{4}$")
SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
REQUIRED_TESTS = ("boot", "io-integrity", "error-recovery", "stress")


def build_matrix(root):
    audit = source_evidence(root)
    claims = {}
    firmware = []
    devices = []
    for driver in audit["drivers"]:
        if driver.get("status") != "source-evidence-only":
            continue
        mod = driver["module"]
        for e in driver.get("pci_evidence", []):
            record = {
                "driver": mod,
                "source": e["source_file"],
                "line": e["evidence_line"],
                "match_type": e["kind"],
                "interpretation": e["interpretation"],
                "vendor_id": e.get("vendor_id"),
                "device_id": e.get("device_id"),
                "pci_class": e.get("class_code"),
                "verified": False,
            }
            devices.append(record)
            if record["vendor_id"] and record["device_id"]:
                pair = (record["vendor_id"], record["device_id"])
                claims.setdefault(pair, set()).add(mod)
        # Reviewed packed (DID<<16)|VID probe tables missed by D0.2's
        # literal pcimatch/switch->did scanner. These remain candidates.
        if mod in ("ether8169", "etherigbe"):
            packed = packed_pci_candidates(
                (root / driver["source_file"]).read_text(encoding="utf-8"),
                driver["source_file"])
            for e in packed:
                devices.append({
                    "driver": mod, "source": e["source_file"],
                    "line": e["evidence_line"], "match_type": e["kind"],
                    "interpretation": e["interpretation"],
                    "vendor_id": e["vendor_id"], "device_id": e["device_id"],
                    "pci_class": None, "verified": False,
                })
                claims.setdefault((e["vendor_id"], e["device_id"]), set()).add(mod)
        for f in driver.get("firmware_references", []):
            path = f["reference"]
            firmware.append({
                "driver": mod,
                "source": driver["source_file"],
                "line": f["evidence_line"],
                "reference": path,
                "reference_kind": f["kind"],
                "is_template": "%" in path,
                "payload_included_by_audit": False,
                "payload_available_on_target": "unknown",
                "redistribution_rights": "not-reviewed",
            })
    devices.sort(key=lambda d: (d["driver"], d["line"], d["match_type"], d["device_id"] or ""))
    firmware.sort(key=lambda f: (f["driver"], f["line"], f["reference"]))
    collisions = [
        {"vendor_id": vendor, "device_id": device, "candidate_drivers": sorted(drivers)}
        for (vendor, device), drivers in sorted(claims.items())
        if len(drivers) > 1
    ]
    return {
        "schema": "ryzova-driver-source-matrix/v1",
        "architecture": "amd64",
        "source_config_sha256": audit["configuration_sha256"],
        "scope": "15 selected modules; subset of configured pc64 source, not full USB/PCI model list",
        "warning": "SOURCE CANDIDATES ONLY: no physical devices qualified",
        "counts": {
            "drivers_inspected": audit["summary"]["review_modules"],
            "source_probe_records": len(devices),
            "fully_specified_vendor_device_records": sum(
                bool(d["vendor_id"] and d["device_id"]) for d in devices),
            "class_selector_records": sum(d["match_type"] == "pci-class-condition" for d in devices),
            "firmware_reference_records": len(firmware),
            "candidate_id_conflicts": len(collisions),
            "real_hardware_verified": 0,
        },
        "device_probe_evidence": devices,
        "firmware_evidence": firmware,
        "candidate_id_conflicts": collisions,
        "not_enumerated": [
            "USB peripheral VID/PID support", "symbolic PCI IDs / packed tables",
            "runtime-dependent PCI exceptions", "actual device revision compatibility",
            "firmware redistribution rights", "BIOS/ACPI integration",
            "modern GPU acceleration", "suspend/resume and battery tests",
        ],
    }


def validate_evidence(evidence):
    errors = []
    if evidence.get("schema") != "ryzova-physical-driver-tests/v1":
        errors.append("invalid-physical-test-schema")
    records = evidence.get("test_records")
    if not isinstance(records, list):
        errors.append("test_records-must-be-a-list")
        records = []
    for i, row in enumerate(records):
        if not isinstance(row, dict):
            errors.append(f"test-record-{i}-not-object")
            continue
        for key in ("driver", "vendor_id", "device_id", "kernel_commit",
                    "device_revision", "firmware_version", "test_operator",
                    "test_date", "log_sha256"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                errors.append(f"test-record-{i}-missing-{key}")
        if row.get("vendor_id") and not HEX4.fullmatch(row["vendor_id"]):
            errors.append(f"test-record-{i}-invalid-vendor-id")
        if row.get("device_id") and not HEX4.fullmatch(row["device_id"]):
            errors.append(f"test-record-{i}-invalid-device-id")
        if row.get("kernel_commit") and not SHA40.fullmatch(row["kernel_commit"]):
            errors.append(f"test-record-{i}-invalid-kernel-commit")
        if row.get("log_sha256") and not re.fullmatch(r"[0-9a-fA-F]{64}", row["log_sha256"]):
            errors.append(f"test-record-{i}-invalid-log-digest")
        tests = row.get("tests")
        if not isinstance(tests, dict):
            errors.append(f"test-record-{i}-missing-tests")
        elif not all(tests.get(t) is True for t in REQUIRED_TESTS):
            errors.append(f"test-record-{i}-required-tests-not-passed")
        if row.get("attestation") != "human-review-required":
            errors.append(f"test-record-{i}-human-review-policy-invalid")
    return errors


def evaluate_release(matrix, physical):
    errors = validate_evidence(physical)
    if matrix["counts"]["real_hardware_verified"] != 0:
        errors.append("source-matrix-must-not-self-certify-real-hardware")
    recorded = physical.get("test_records", [])
    recorded = recorded if isinstance(recorded, list) else []
    approved = physical.get("maintainer_approval")
    # This checker cannot cryptographically verify a person's identity,
    # actual test hardware or redistribution permission. Human review remains
    # necessary even if every field is filled in.
    blockers = []
    if errors:
        blockers.append("physical-evidence-schema-errors")
    if not recorded:
        blockers.append("no-physical-hardware-test-records")
    if not approved:
        blockers.append("maintainer-approval-missing")
    if physical.get("license_clearance") is not True:
        blockers.append("binary-license-clearance-missing")
    if not physical.get("independent_lab_review"):
        blockers.append("independent-lab-review-missing")
    blockers.append("human-release-authorization-required")
    return {
        "schema": "ryzova-driver-release-gate/v1",
        "gate": "blocked",
        "auto_release_allowed": False,
        "blockers": blockers,
        "evidence_errors": errors,
        "physical_test_record_count": len(recorded),
        "source_probe_candidate_count": matrix["counts"]["source_probe_records"],
        "message": "CI evidence validation is not a replacement for tested hardware, rights review, and a human release decision.",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--physical-evidence", default="ryzova/drivers/physical-tests.json")
    p.add_argument("--output", type=Path, default=Path("artifacts/drivers/d-series-matrix.json"))
    p.add_argument("--gate-output", type=Path, default=Path("artifacts/drivers/d-series-release-gate.json"))
    p.add_argument("--enforce-release", action="store_true", help="Return failure until separately authorized for release")
    args = p.parse_args()
    root = args.root.resolve()
    matrix = build_matrix(root)
    evidence_path = (root / args.physical_evidence).resolve()
    if not evidence_path.is_relative_to(root):
        p.error("physical evidence must be inside repository")
    physical = json.loads(evidence_path.read_text(encoding="utf-8"))
    gate = evaluate_release(matrix, physical)
    for path, obj in [(args.output, matrix), (args.gate_output, gate)]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"matrix": matrix["counts"], "release_gate": gate["gate"],
                      "blockers": gate["blockers"], "errors": gate["evidence_errors"]}, indent=2))
    if gate["evidence_errors"]:
        raise SystemExit(2)
    if args.enforce_release:
        raise SystemExit(3)  # Explicit fail-closed until human release decision.


if __name__ == "__main__":
    main()
