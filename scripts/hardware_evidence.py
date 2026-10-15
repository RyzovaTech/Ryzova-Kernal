#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""D0.2: audit PCI probe evidence and firmware references in selected AMD64 drivers.

No extracted ID is a promise that a physical device works. Source code is
untrusted evidence until probe paths, firmware permissions and real hardware
have been examined and tested.
"""
import argparse
import json
import re
from pathlib import Path

from driver_inventory import inventory

# Intentionally bounded review set. Expand ONLY after reviewing each driver's
# probe code; this list is not all device support in the source tree.
REVIEW_MODULES = (
    "etheri225", "ether82598", "etherx550", "etheriwl", "etherwpi",
    "etherrt2860", "ether8169", "etherigbe", "ethervirtio",
    "ethervirtio10", "sdnvme", "sdiahci", "sdvirtio10",
    "usbxhcipci", "audiohda",
)
PCIMATCH = re.compile(
    r"\bpcimatch\s*\(\s*([A-Za-z]\w*)\s*,\s*(0x[0-9a-fA-F]+|[0-9]+)\s*,\s*"
    r"(0x[0-9a-fA-F]+|[0-9]+)\s*\)"
)
SWITCH_DID = re.compile(r"\bswitch\s*\(\s*([A-Za-z]\w*)->did\s*\)\s*\{")
CASES = re.compile(r"\bcase\s+(0x[0-9a-fA-F]{1,4})\s*:")
FW_PATH = re.compile(r'"/lib/firmware/([A-Za-z0-9_.%+-]+)"')
FW_ASSIGN = re.compile(r'\bfwname\s*=\s*"([A-Za-z0-9_.+-]+)"')
# Explicit class tuples: compare to the actual source strings. A class tuple
# is not a finite PCI device-ID list.
CLASS_SELECTORS = {
    "sdnvme": ((r"p->ccrb\s*!=\s*1", r"p->ccru\s*!=\s*8", r"p->ccrp\s*!=\s*2"), "01:08:02", "negative-filter"),
    "usbxhcipci": ((r"p->ccrb\s*!=\s*Pcibcserial", r"p->ccru\s*!=\s*Pciscusb", r"p->ccrp\s*!=\s*0x30"), "0c:03:30", "negative-filter"),
    "audiohda": ((r"p->ccrb\s*==\s*0x04", r"p->ccru\s*==\s*0x03"), "04:03:*", "positive-filter"),
    "sdiahci": ((r"p->ccrb\s*==\s*Pcibcstore", r"p->ccru\s*==\s*6", r"p->ccrp\s*==\s*1"), "01:06:01", "conditional-fallback"),
}


def strip_c_comments(src):
    # Retain newlines so emitted 1-based line numbers remain stable.
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def line_at(src, offset):
    return src.count("\n", 0, offset) + 1


def scoped_block(src, open_pos):
    """Return balanced switch body; do not confuse unrelated case labels."""
    pos = src.find("{", open_pos)
    if pos == -1:
        return ""
    level = 0
    for i in range(pos, len(src)):
        if src[i] == "{":
            level += 1
        elif src[i] == "}":
            level -= 1
            if level == 0:
                return src[pos + 1:i]
    return ""


def extract_evidence(path, text, module):
    cleaned = strip_c_comments(text)
    matches = []
    for m in PCIMATCH.finditer(cleaned):
        vendor, device = int(m.group(2), 0), int(m.group(3), 0)
        matches.append({
            "kind": "pci-literal-scan",
            "vendor_id": f"{vendor:04x}" if vendor else None,
            "device_id": f"{device:04x}" if device else None,
            "evidence_line": line_at(cleaned, m.start()),
            "source_file": path,
            "interpretation": (
                "exact-literal-probe" if vendor and device else
                "vendor-only-scan" if vendor else "wildcard-scan"
            ),
        })
    # Only assign switch case IDs as *candidates* when the source uses exactly
    # one nonzero vendor in literal pcimatch() calls, and the variable matches.
    for s in SWITCH_DID.finditer(cleaned):
        variable = s.group(1)
        eligible = [(m, int(m.group(2), 0)) for m in PCIMATCH.finditer(cleaned)
                    if m.group(1) == variable and int(m.group(2), 0) != 0]
        vendors = set(v for _, v in eligible)
        if len(vendors) != 1:
            continue
        vendor = next(iter(vendors))
        # Nearby scan rule keeps a distant, unrelated switch from taking the
        # vendor of a scan in some other function.
        nearby = [m for m, _ in eligible if 0 <= s.start()-m.end() <= 1600]
        if not nearby:
            continue
        body = scoped_block(cleaned, s.start())
        if not body:
            continue
        for c in CASES.finditer(body):
            matches.append({
                "kind": "vendor-scoped-switch-candidate",
                "vendor_id": f"{vendor:04x}",
                "device_id": f"{int(c.group(1), 16):04x}",
                "evidence_line": line_at(cleaned, s.end()) + body.count("\n", 0, c.start()),
                "source_file": path,
                "interpretation": "source-probe-candidate-not-hardware-tested",
            })

    # Firmware dependency evidence is limited to runtime path references and
    # names assigned to fwname. No firmware payload or license is imported.
    firmware = []
    for m in FW_PATH.finditer(cleaned):
        firmware.append({
            "reference": "/lib/firmware/" + m.group(1),
            "evidence_line": line_at(cleaned, m.start()),
            "kind": "runtime-path-reference",
            "redistribution_status": "not-reviewed",
        })
    for m in FW_ASSIGN.finditer(cleaned):
        firmware.append({
            "reference": m.group(1),
            "evidence_line": line_at(cleaned, m.start()),
            "kind": "runtime-firmware-name",
            "redistribution_status": "not-reviewed",
        })
    if module in CLASS_SELECTORS:
        patterns, class_code, rule = CLASS_SELECTORS[module]
        if all(re.search(pattern, cleaned) for pattern in patterns):
            start = re.search(patterns[0], cleaned)
            matches.append({
                "kind": "pci-class-condition",
                "class_code": class_code,
                "interpretation": rule + "-requires-probe-validation",
                "evidence_line": line_at(cleaned, start.start()),
                "source_file": path,
            })
    matches.sort(key=lambda e: (e["evidence_line"], e["kind"], e.get("device_id") or ""))
    firmware.sort(key=lambda e: (e["evidence_line"], e["reference"]))
    return matches, firmware


def build(root):
    conf_path = "sys/src/9/pc64/pc64"
    data = inventory((root / conf_path).read_text(encoding="utf-8"), root)
    lookup = {e["module"]: e for e in data["entries"] if e["enabled"]}
    items = []
    for name in REVIEW_MODULES:
        entry = lookup.get(name)
        if entry is None or not entry["source_file"]:
            items.append({"module": name, "status": "needs-manual-review",
                          "reason": "not-enabled-or-source-unresolved"})
            continue
        path = entry["source_file"]
        matches, firmware = extract_evidence(
            path, (root / path).read_text(encoding="utf-8"), name)
        items.append({
            "module": name, "family": entry["family"], "source_file": path,
            "status": "source-evidence-only", "pci_evidence": matches,
            "usb_ids": [], "usb_ids_status": "not-enumerated",
            "firmware_references": firmware,
            "physical_hardware_status": "unverified",
            "license_review": "not-reviewed",
        })
    return {
        "schema": "ryzova-hardware-evidence/v1",
        "platform": "amd64",
        "configuration_sha256": data["config_sha256"],
        "scope": "Selected enabled driver modules; not a complete hardware support list",
        "warning": "PCI IDs and class filters reflect SOURCE PROBE CANDIDATES, not proven device compatibility",
        "summary": {
            "review_modules": len(items),
            "with_source_evidence": sum(v["status"] == "source-evidence-only" for v in items),
            "pci_exact_literal_probes": sum(
                e["interpretation"] == "exact-literal-probe" for v in items for e in v.get("pci_evidence", [])),
            "pci_vendor_scoped_candidates": sum(
                e["kind"] == "vendor-scoped-switch-candidate" for v in items for e in v.get("pci_evidence", [])),
            "pci_class_conditions": sum(
                e["kind"] == "pci-class-condition" for v in items for e in v.get("pci_evidence", [])),
            "firmware_path_or_name_references": sum(len(v.get("firmware_references", [])) for v in items),
            "physically_verified_device_count": 0,
        },
        "drivers": items,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    root = args.root.resolve()
    result = json.dumps(build(root), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
        print(json.dumps(json.loads(result)["summary"], indent=2))
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
