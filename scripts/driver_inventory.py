#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate a deterministic AMD64 pc64 driver/configuration inventory.

This indexes configuration entries and source existence. It does not establish
device-ID coverage, firmware rights, ABI compatibility, or physical support.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

SECTIONS = {"dev", "link", "misc", "ip", "port", "bootdir"}
INDEX_SECTIONS = {"dev", "link", "misc", "ip"}
MODULE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# Only recognize known module families in commented-out configuration lines.
# This prevents ordinary remarks (e.g. '# should be obsolete') from becoming
# false disabled-driver entries.
COMMENTED_MODULE = re.compile(
    r"^(?:dev|ether|audio|vga|sd|usb|uart|arch|cputemp|pmmc|pcmcia|"
    r"lpt|floppy|i82365|apm|mtrr|dtracy|pci|mp|irq|mouse)"
    r"[A-Za-z0-9_]*$"
)
SOURCE_DIRS = (
    "sys/src/9/pc",
    "sys/src/9/port",
    "sys/src/9/ip",
    "sys/src/9/pc64",
)


def family(module):
    if module.startswith(("ether", "wifi")):
        return "network"
    if module.startswith(("sd", "aoe")):
        return "storage"
    if module.startswith(("usb",)):
        return "usb"
    if module.startswith(("audio",)):
        return "audio"
    if module.startswith(("vga", "screen", "draw")):
        return "display"
    if module.startswith(("kbd", "mouse")):
        return "input"
    if module.startswith(("uart",)):
        return "serial"
    if module.startswith(("pci", "arch", "pnp", "apic", "irq", "pmmc", "mp", "cputemp")):
        return "platform"
    return "core_or_other"


def find_source(root, section, module):
    """Find direct .c matches; this is source presence, not active probe support."""
    candidates = [module + ".c"]
    if section == "dev" and not module.startswith("dev"):
        candidates.insert(0, "dev" + module + ".c")
    for dirname in SOURCE_DIRS:
        for candidate in candidates:
            path = root / dirname / candidate
            if path.is_file():
                return path.relative_to(root).as_posix()
    return None


def inventory(config_text, root, config_path="sys/src/9/pc64/pc64"):
    current_section = None
    entries = []
    for lineno, line in enumerate(config_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        # Header names must be unindented and exact; comments never open sections.
        if line == stripped and stripped in SECTIONS:
            current_section = stripped
            continue
        if current_section not in INDEX_SECTIONS:
            continue

        disabled = stripped.startswith("#")
        body = stripped[1:].strip() if disabled else stripped
        body = body.split("#", 1)[0].strip()
        if not body:
            continue
        tokens = body.split()
        module = tokens[0]
        if not MODULE.fullmatch(module):
            continue
        if disabled and not COMMENTED_MODULE.fullmatch(module):
            continue

        source = find_source(root, current_section, module)
        entries.append({
            "line": lineno,
            "section": current_section,
            "module": module,
            "enabled": not disabled,
            "arguments": tokens[1:],
            "family": family(module),
            "source_file": source,
            "source_present": source is not None,
            # Deliberately unknown until each driver is inspected against
            # hardware manuals, probe logic, firmware and actual devices.
            "pci_usb_ids": [],
            "device_ids_review": "not-reviewed",
            "firmware_review": "not-reviewed",
            "physical_hardware_status": "unverified",
            "test_evidence": [],
        })

    return {
        "schema": "ryzova-driver-inventory/v1",
        "license": "AGPL-3.0-only",
        "platform": "amd64",
        "configuration": config_path,
        "config_sha256": hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
        "meaning": "Configuration and source index; NOT hardware compatibility certification",
        "counts": {
            "entries": len(entries),
            "enabled": sum(x["enabled"] for x in entries),
            "disabled": sum(not x["enabled"] for x in entries),
            "source_present": sum(x["source_present"] for x in entries),
        },
        "entries": entries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1],
        help="Repository root (defaults to script's parent repository)"
    )
    parser.add_argument(
        "--config", default="sys/src/9/pc64/pc64",
        help="Path relative to repository root"
    )
    parser.add_argument(
        "--output", type=Path,
        help="Output JSON file; if omitted, write to stdout"
    )
    args = parser.parse_args()
    root = args.root.resolve()
    config_file = (root / args.config).resolve()
    if not config_file.is_relative_to(root):
        parser.error("--config must remain inside repository root")
    if not config_file.is_file():
        parser.error("kernel configuration not found: " + str(config_file))

    data = inventory(config_file.read_text(encoding="utf-8"), root, args.config)
    result = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
        print("Wrote %d entries (%d enabled, %d disabled) to %s" % (
            data["counts"]["entries"], data["counts"]["enabled"],
            data["counts"]["disabled"], args.output))
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
