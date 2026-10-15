#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Preliminary, reproducible tracked-file license inventory, NOT legal clearance."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "lib/legal/NOTICE",
    "lib/legal/mit",
    "lib/legal/afpl",
    "lib/legal/gpl",
    "lib/legal/ofl",
    "LICENSE.md",
    "LICENSES/AGPL-3.0-only.txt",
    "COMMERCIAL-LICENSING.md",
    "TRADEMARKS.md",
    "CONTRIBUTING.md",
    "docs/CONTRIBUTOR-LICENSING.md",
    "docs/BUILD-STANDARDS.md",
    "docs/BRANDING.md",
)
RYZOVA_CODE = ("scripts/audit_licenses.py", "scripts/verify-foundation.sh")
EXCEPTIONS = (
    ("lib/font/bit/lucida/", "Restricted Lucida screen fonts"),
    ("sys/lib/postscript/font/", "Restricted Lucida printer fonts"),
    ("sys/lib/ghostscript/font/", "GPL-2.0 printer fonts"),
    ("sys/src/cmd/gs/", "Aladdin Free Public License"),
    ("lib/font/bit/source/", "SIL Open Font License"),
    ("lib/font/bit/terminus/", "SIL Open Font License"),
)
MARKER = re.compile(r"(?i)(?:^|/)(?:LICENSE(?:[-._].*)?|LICEN[CS]E(?:[-._].*)?|COPYING(?:[-._].*)?|COPYRIGHT(?:[-._].*)?|NOTICE(?:[-._].*)?)$")
SPDX = re.compile(rb"SPDX-License-Identifier:\s*([^\s\r\n*]+)")


def tracked_paths() -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return sorted(x.decode("utf-8", errors="surrogateescape") for x in raw.split(b"\x00") if x)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts/license-inventory.json")
    args = parser.parse_args()
    paths = tracked_paths()
    tracked = set(paths)
    errors: list[str] = []

    for name in REQUIRED:
        if name not in tracked or not (ROOT / name).is_file():
            errors.append(f"Missing required legal/policy file: {name}")
    notice_file = ROOT / "lib/legal/NOTICE"
    if notice_file.is_file():
        notice = notice_file.read_text(encoding="utf-8", errors="replace")
        for word in ("MIT license", "exceptions", "Aladdin Free Public License", "SIL Open Font License"):
            if word not in notice:
                errors.append(f"9front notice missing expected section: {word}")
    license_file = ROOT / "LICENSES/AGPL-3.0-only.txt"
    if license_file.is_file():
        content = license_file.read_text(encoding="utf-8", errors="replace")
        if not content.startswith("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007"):
            errors.append("Bundled AGPL text does not match expected SPDX license opening")

    copyright_markers = [p for p in paths if MARKER.search(p)]
    spdx_files: list[dict[str, str]] = []
    for name in paths:
        # Bounded reads: inventory common source formats without scanning binary data.
        if not name.endswith((".c", ".h", ".s", ".S", ".py", ".sh", ".mk", ".rs", ".go", ".y", ".l")):
            continue
        try:
            with (ROOT / name).open("rb") as handle:
                prefix = handle.read(2048)
        except OSError as exc:
            errors.append(f"Could not read {name}: {exc}")
            continue
        match = SPDX.search(prefix)
        if match:
            spdx_files.append({"path": name, "spdx": match.group(1).decode("ascii", errors="replace")})

    for name in RYZOVA_CODE:
        if name not in tracked:
            errors.append(f"Missing Ryzova script: {name}")
        elif not any(item["path"] == name and item["spdx"] == "AGPL-3.0-only" for item in spdx_files):
            errors.append(f"Missing AGPL-3.0-only SPDX identifier on Ryzova script: {name}")

    mapped_exceptions = []
    for prefix, reason in EXCEPTIONS:
        matched = sum(1 for p in paths if p.startswith(prefix))
        mapped_exceptions.append({"path_prefix": prefix, "upstream_notice": reason, "tracked_file_count": matched})
        if matched == 0:
            errors.append(f"Expected upstream exception path has no tracked files: {prefix}")

    result = {
        "description": "Preliminary tracked-file license inventory; NOT legal clearance",
        "tracked_file_count": len(paths),
        "copyright_license_notice_paths": copyright_markers,
        "explicit_spdx_files": spdx_files,
        "upstream_exceptions": mapped_exceptions,
        "warnings": [
            "SPDX identifiers are not a definitive determination of actual license rights.",
            "Unmarked third-party assets may have additional terms; manual review is required.",
            "Commercial license applicability requires specific documented ownership and grants.",
        ],
        "errors": errors,
    }
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Tracked files: {len(paths)}")
    print(f"Files named LICENSE/COPYING/COPYRIGHT/NOTICE: {len(copyright_markers)}")
    print(f"Source files with detected SPDX headers: {len(spdx_files)}")
    print(f"Audit inventory written to {output.relative_to(ROOT)}")
    for item in mapped_exceptions:
        print(f"Known license exception {item['path_prefix']}: {item['tracked_file_count']} tracked file(s)")
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    print("This tool does not replace human file-level legal review.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
