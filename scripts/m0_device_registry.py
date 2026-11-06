#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M0 source-only PCI/USB candidate index; never binds or certifies hardware."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

SCHEMA = "ryzova-m0-device-registry/v1"
FW_SCHEMA = "ryzova-m0-firmware-manifest/v1"
HEX2 = re.compile(r"[0-9a-f]{2}\Z")
HEX4 = re.compile(r"[0-9a-f]{4}\Z")
SYMBOL = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
MODULE = re.compile(r"[a-z][a-z0-9_]{1,63}\Z")


class RegistryError(ValueError):
    pass


def fail(reason):
    raise RegistryError(reason)


def read_json(path):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                fail("duplicate JSON key: " + key)
            obj[key] = value
        return obj
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def source_path(root, raw):
    if not isinstance(raw, str) or not raw or raw.startswith("/") or "\\" in raw:
        fail("source path must be relative")
    if any(t in ("", ".", "..") for t in raw.split("/")):
        fail("source path traversal")
    path = (root / raw).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        fail("source file missing/outside repository: " + raw)
    return path


def hexcode(x, n, label):
    pat = HEX4 if n == 4 else HEX2
    if not isinstance(x, str) or not pat.fullmatch(x):
        fail(label + " must be lowercase fixed-width hex")
    return int(x, 16)


def parse_rule(raw, root):
    if not isinstance(raw, dict):
        fail("rule must be an object")
    allowed = {"id", "bus", "driver", "source_file", "selector", "revision_min",
               "revision_max", "firmware_id", "evidence_level", "binding_enabled"}
    if set(raw) != allowed:
        fail("rule fields must match schema exactly")
    rid, bus, driver = raw["id"], raw["bus"], raw["driver"]
    if not isinstance(rid, str) or not SYMBOL.fullmatch(rid):
        fail("invalid rule id")
    if bus not in ("pci", "usb") or not isinstance(driver, str) or not MODULE.fullmatch(driver):
        fail("invalid bus/driver for " + rid)
    source_path(root, raw["source_file"])
    if raw["evidence_level"] != "source-candidate" or raw["binding_enabled"] is not False:
        fail("M0 cannot self-promote evidence or enable binding: " + rid)
    lo, hi = raw["revision_min"], raw["revision_max"]
    limit = 255 if bus == "pci" else 65535
    if type(lo) is not int or type(hi) is not int or not 0 <= lo <= hi <= limit:
        fail("invalid revision bounds: " + rid)
    fwid = raw["firmware_id"]
    if fwid is not None and (not isinstance(fwid, str) or not SYMBOL.fullmatch(fwid)):
        fail("invalid firmware reference: " + rid)
    sel = raw["selector"]
    if not isinstance(sel, dict):
        fail("selector must be an object")
    if set(sel) == {"vendor_id", "device_id"}:
        key = (bus, hexcode(sel["vendor_id"], 4, "vendor_id"),
               hexcode(sel["device_id"], 4, "device_id"))
        kind = "exact"
    elif set(sel) in ({"class", "subclass"}, {"class", "subclass", "protocol"}):
        proto = hexcode(sel["protocol"], 2, "protocol") if "protocol" in sel else None
        key = (bus, hexcode(sel["class"], 2, "class"),
               hexcode(sel["subclass"], 2, "subclass"), proto)
        kind = "class"
    else:
        fail("selector must be exact ID pair or class tuple: " + rid)
    return {"id": rid, "bus": bus, "driver": driver, "kind": kind, "key": key,
            "lo": lo, "hi": hi, "firmware_id": fwid, "source_file": raw["source_file"]}


def read_firmware(raw):
    if not isinstance(raw, dict) or raw.get("schema") != FW_SCHEMA or set(raw) != {"schema", "entries"}:
        fail("invalid firmware manifest schema")
    entries = raw["entries"]
    if not isinstance(entries, list):
        fail("firmware entries must be a list")
    ids = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "path_hint", "sha256", "redistribution", "payload_included"}:
            fail("invalid firmware entry fields")
        eid = entry["id"]
        if not isinstance(eid, str) or not SYMBOL.fullmatch(eid) or eid in ids:
            fail("invalid/duplicate firmware id")
        ids.add(eid)
        if not isinstance(entry["path_hint"], str) or not entry["path_hint"].startswith("/lib/firmware/"):
            fail("invalid firmware path hint")
        sha = entry["sha256"]
        if sha is not None and (not isinstance(sha, str) or not re.fullmatch("[0-9a-f]{64}", sha)):
            fail("invalid firmware digest")
        if entry["redistribution"] not in ("not-reviewed", "not-permitted", "cleared-by-human-review"):
            fail("invalid redistribution status")
        if entry["payload_included"] is not False:
            fail("M0 cannot bundle firmware")
    return ids


class CandidateIndex:
    def __init__(self, registry, firmware, root):
        if (not isinstance(registry, dict) or
                set(registry) != {"schema", "binding_enabled", "rules"} or
                registry["schema"] != SCHEMA or registry["binding_enabled"] is not False):
            fail("invalid M0 registry schema/binding policy")
        if not isinstance(registry["rules"], list):
            fail("rules must be a list")
        fwid = read_firmware(firmware)
        self.exact = defaultdict(list)
        self.classes = defaultdict(list)
        seen = set()
        self.rules = []
        for raw in registry["rules"]:
            r = parse_rule(raw, root)
            if r["id"] in seen:
                fail("duplicate rule id: " + r["id"])
            if r["firmware_id"] is not None and r["firmware_id"] not in fwid:
                fail("unknown firmware id: " + r["firmware_id"])
            seen.add(r["id"])
            self.rules.append(r)
            (self.exact if r["kind"] == "exact" else self.classes)[r["key"]].append(r)
        for bucket in (self.exact, self.classes):
            for key, values in bucket.items():
                last_hi = -1
                for r in sorted(values, key=lambda x: (x["lo"], x["hi"])):
                    if r["lo"] <= last_hi:
                        fail("overlapping same-selector revisions: " + str(key))
                    last_hi = r["hi"]

    def verify_pc64_configuration(self, root):
        """Fail if a kernel candidate refers to a disabled/missing pc64 module."""
        from driver_inventory import inventory
        config = root / "sys/src/9/pc64/pc64"
        data = inventory(config.read_text(encoding="utf-8"), root)
        enabled = {(e["module"], e["source_file"]) for e in data["entries"]
                   if e["enabled"] and e["source_present"]}
        for r in self.rules:
            if r["source_file"].startswith("sys/src/9/") and (r["driver"], r["source_file"]) not in enabled:
                fail("kernel module not active or source mismatch: " + r["id"])

    @staticmethod
    def _select(rows, revision):
        eligible = [r for r in rows if r["lo"] <= revision <= r["hi"]]
        if len(eligible) > 1:
            fail("ambiguous runtime match")
        return eligible[0] if eligible else None

    def match(self, bus, vendor, device, classcode, subclass, protocol, revision):
        limit = 255 if bus == "pci" else 65535
        if bus not in ("pci", "usb") or any(
            type(v) is not int or not 0 <= v <= high
            for v, high in [(vendor, 65535), (device, 65535), (classcode, 255),
                            (subclass, 255), (protocol, 255), (revision, limit)]
        ):
            fail("invalid observed device tuple")
        for rows in (self.exact.get((bus, vendor, device), ()),
                     self.classes.get((bus, classcode, subclass, protocol), ()),
                     self.classes.get((bus, classcode, subclass, None), ())):
            rule = self._select(rows, revision)
            if rule:
                return {"result": "source-candidate", "rule_id": rule["id"],
                        "driver": rule["driver"], "source_file": rule["source_file"],
                        "firmware_id": rule["firmware_id"],
                        "hardware_verified": False, "auto_bind_allowed": False}
        return {"result": "unknown", "rule_id": None, "driver": None,
                "hardware_verified": False, "auto_bind_allowed": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--registry", default="ryzova/drivers/m0-device-registry.json")
    p.add_argument("--firmware", default="ryzova/drivers/m0-firmware-manifest.json")
    p.add_argument("--match", choices=("pci", "usb"))
    for x in ("vendor", "device", "classcode", "subclass", "protocol", "revision"):
        p.add_argument("--" + x, type=lambda text: int(text, 16), default=0)
    args = p.parse_args()
    try:
        root = args.root.resolve()
        reg = source_path(root, args.registry)
        fw = source_path(root, args.firmware)
        index = CandidateIndex(read_json(reg), read_json(fw), root)
        index.verify_pc64_configuration(root)
        if args.match:
            output = index.match(args.match, args.vendor, args.device, args.classcode,
                                 args.subclass, args.protocol, args.revision)
        else:
            output = {"result": "valid-source-only-registry",
                      "rule_count": len(index.rules),
                      "firmware_review_count": len(read_json(fw)["entries"]),
                      "hardware_verified": False, "auto_bind_allowed": False}
    except (RegistryError, OSError, ValueError) as exc:
        p.exit(1, "M0 registry rejected: " + str(exc) + "\n")
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
