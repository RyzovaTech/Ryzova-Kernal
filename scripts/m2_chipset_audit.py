#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M2 independent PCI family provenance and fail-closed qualification audit.

The registry is for discovery/diagnostics only. No new driver is attached by
this script, and verified/certified device counts are always zero.
"""
import argparse
import json
from pathlib import Path
import re
import sys

from m0_device_registry import CandidateIndex, RegistryError, read_json
from m0_native_rules import OUTPUT, generate

SCHEMA = "ryzova-m2-chipset-families/v1"
VENDORS = {"intel": "8086", "amd": "1022", "realtek": "10ec"}
CATEGORIES = {"network", "audio", "wifi"}
TRACKS = ("modern-amd64", "legacy-amd64")
HEX = re.compile("[0-9a-f]{4}\\Z")


def audit(manifest, registry, firmware, root):
    if (not isinstance(manifest, dict) or
            set(manifest) != {"schema", "policy", "tracks", "entries"} or
            manifest["schema"] != SCHEMA or
            manifest["policy"] != "source-candidate-no-attach" or
            manifest["tracks"] != list(TRACKS)):
        raise RegistryError("invalid M2 family schema/release policy")
    if not isinstance(manifest["entries"], list) or not (12 <= len(manifest["entries"]) <= 512):
        raise RegistryError("M2 requires reviewed chipset families and bounded records")
    index = CandidateIndex(registry, firmware, root)
    index.verify_pc64_configuration(root)
    rules = {r["id"]: r for r in registry["rules"]}
    fw = {r["id"]: r for r in firmware["entries"]}
    seen = set()
    vendors, represented = set(), set()
    firmware_blocked = []
    output = []
    for row in manifest["entries"]:
        fields = {"id", "vendor_family", "track", "category", "driver", "source_file",
                  "vendor_id", "device_id", "source_anchor", "firmware_id",
                  "certified", "auto_bind_allowed"}
        if not isinstance(row, dict) or set(row) != fields:
            raise RegistryError("invalid M2 entry fields")
        name = row["id"]
        vendor = row["vendor_family"]
        track = row["track"]
        category = row["category"]
        did = row["device_id"]
        vid = row["vendor_id"]
        if (not isinstance(name, str) or not re.fullmatch("[a-z][a-z0-9-]{3,63}", name)
                or name in seen):
            raise RegistryError("duplicate or malformed family id")
        seen.add(name)
        if vendor not in VENDORS or vid != VENDORS[vendor] or track not in (*TRACKS, "both") or category not in CATEGORIES:
            raise RegistryError("unreviewed chipset vendor, target track or category")
        if not isinstance(did, str) or not HEX.fullmatch(did) or not HEX.fullmatch(vid):
            raise RegistryError("PCI IDs must be lowercase four-digit hex")
        if row["certified"] is not False or row["auto_bind_allowed"] is not False:
            raise RegistryError("M2 sources cannot certify or attach devices")
        if not isinstance(row["source_anchor"], str) or not (12 <= len(row["source_anchor"]) <= 128):
            raise RegistryError("invalid source anchor")
        if did not in row["source_anchor"].lower():
            raise RegistryError("source anchor must mention exact device id")
        path = row["source_file"]
        if (not isinstance(path, str) or not path.startswith("sys/src/9/") or
                "/.." in path or "\\" in path):
            raise RegistryError("unsafe kernel source path")
        source = (root / path).resolve()
        if not source.is_relative_to(root.resolve()) or not source.is_file():
            raise RegistryError("missing source file")
        code = source.read_text(encoding="utf-8")
        if row["source_anchor"] not in code or ("0x" + vid) not in code.lower():
            raise RegistryError("chipset PCI ID lacks exact source evidence: " + name)
        rid = "m2-" + name + "-candidate"
        rule = rules.get(rid)
        if (not isinstance(rule, dict) or rule["bus"] != "pci" or
                rule["selector"] != {"vendor_id": vid, "device_id": did} or
                rule["driver"] != row["driver"] or
                rule["source_file"] != path or
                rule["revision_min"] != 0 or rule["revision_max"] != 255 or
                rule["firmware_id"] != row["firmware_id"] or
                rule["evidence_level"] != "source-candidate" or
                rule["binding_enabled"] is not False):
            raise RegistryError("M2 registry/source mismatch: " + rid)
        fwid = row["firmware_id"]
        if fwid is not None:
            if fwid not in fw:
                raise RegistryError("unreviewed/missing firmware metadata")
            record = fw[fwid]
            if record["payload_included"] is not False:
                raise RegistryError("M2 cannot redistribute firmware")
            # No physical firmware checksum or license attestation is implied.
            firmware_blocked.append(rid)
        vendors.add(vendor)
        represented.add(track)
        output.append({"rule_id": rid, "vendor_family": vendor, "driver": row["driver"],
                       "platform": track, "candidate_only": True,
                       "firmware_review_blocked": fwid is not None})
    if vendors != set(VENDORS):
        raise RegistryError("M2 must include Intel AMD Realtek")
    if "legacy-amd64" not in represented or "modern-amd64" not in represented:
        raise RegistryError("modern and legacy targets must be preserved")
    if generate(root) != (root / OUTPUT).read_text(encoding="utf-8"):
        raise RegistryError("native generated PCI rules differ from reviewed registry")
    return {
        "schema": "ryzova-m2-chipset-audit/v1",
        "status": "source-integrated-hardware-unverified",
        "release_gate": "blocked",
        "vendor_families": sorted(vendors),
        "source_candidate_ids": len(output),
        "physical_verified_models": 0,
        "certified_models": 0,
        "legacy_track_present": True,
        "modern_track_present": True,
        "auto_bind_allowed": False,
        "firmware_review_blocked": sorted(firmware_blocked),
        "candidates": output,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    root = args.root.resolve()
    try:
        report = audit(
            read_json(root / "ryzova/drivers/m2-chipset-families.json"),
            read_json(root / "ryzova/drivers/m0-device-registry.json"),
            read_json(root / "ryzova/drivers/m0-firmware-manifest.json"),
            root,
        )
    except (OSError, ValueError, RegistryError) as exc:
        p.exit(1, "M2 source audit rejected: " + str(exc) + "\n")
    data = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
