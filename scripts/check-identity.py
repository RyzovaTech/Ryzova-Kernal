#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail if Ryzova native kernel device/version metadata and profile diverge."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
meta=json.loads((ROOT/"ryzova/metadata/kernel-version.json").read_text())
profile=json.loads((ROOT/"ryzova/config/amd64.default.json").read_text())
driver=(ROOT/"sys/src/9/port/devryzova.c").read_text()
config=(ROOT/"sys/src/9/pc64/pc64").read_text()
assert meta["name"]=="Ryzova Kernel"
assert meta["version"] and meta["status"]=="experimental"
assert meta["device"]=="#Z"
assert meta["abi"]=="experimental-0"
assert meta["version"] in driver
assert meta["foundation"] in driver
assert meta["abi"] in driver
assert "ryzovadevtab" in driver
assert "SPDX-License-Identifier: AGPL-3.0-only" in driver
assert any(line.strip().startswith("ryzova") for line in config.splitlines())
assert profile["architecture"]=="amd64"
assert profile["native_tool"]=="mk"
assert profile["kernel_source"]=="sys/src/9/pc64"
assert profile["kernel_binary"]=="9pc64"
assert profile["features"]["ryzova_device"] is True
print("PASS: Ryzova device identity, native kernel config, and build profile agree.")
