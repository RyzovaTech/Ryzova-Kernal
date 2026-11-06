#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Extract explicitly packed PCI vendor/device literals from reviewed probe switches.

Review scope is intentionally only ethernet drivers known to use
    (p->did<<16)|p->vid
and literal/enum case arms. A case arm is a probe *candidate*, not a
hardware support or release certification.
"""
import re

from hardware_evidence import scoped_block, strip_c_comments

PACKED_DEF = re.compile(
    r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*\(\s*0x([0-9A-Fa-f]{1,4})\s*<<\s*16\s*\)"
    r"\s*\|\s*0x([0-9A-Fa-f]{1,4})\s*,?"
)
PACKED_LITERAL = re.compile(
    r"^\s*\(\s*0x([0-9A-Fa-f]{1,4})\s*<<\s*16\s*\)\s*\|\s*0x([0-9A-Fa-f]{1,4})\s*$"
)
PACKED_SWITCH = re.compile(
    r"\bswitch\s*\([^{};]*?\bp->did\s*<<\s*16[^{};]*?\bp->vid[^{};]*?\)\s*\{", re.S
)
CASE = re.compile(r"\bcase\s+([^:]+):")


def packed_pci_candidates(src, path):
    cleaned = strip_c_comments(src)
    defs = {
        m.group(1): (int(m.group(2), 16), int(m.group(3), 16))
        for m in PACKED_DEF.finditer(cleaned)
    }
    records = []
    for scan in PACKED_SWITCH.finditer(cleaned):
        body = scoped_block(cleaned, scan.end() - 1)
        for case in CASE.finditer(body):
            identifier = case.group(1).strip()
            if identifier in defs:
                device, vendor = defs[identifier]
            else:
                literal = PACKED_LITERAL.fullmatch(identifier)
                if literal is None:
                    continue
                device, vendor = int(literal.group(1), 16), int(literal.group(2), 16)
            records.append({
                "source_file": path,
                "evidence_line": cleaned.count("\n", 0, scan.end()) +
                                 body.count("\n", 0, case.start()) + 1,
                "vendor_id": f"{vendor:04x}",
                "device_id": f"{device:04x}",
                "kind": "packed-pci-case-candidate",
                "interpretation": "unverified-source-switch-case",
                "symbol": identifier if identifier in defs else None,
            })
    records.sort(key=lambda d: (d["evidence_line"], d["vendor_id"], d["device_id"]))
    return records
