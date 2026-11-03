# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed MAC-0 provenance/contract audit; never loads or executes Mach-O."""
import argparse
import hashlib
import json
from pathlib import Path

CONTRACT = "ryzova/compat/macos/mac0-contract.json"
SOURCES = (
    "ryzova/compat/macos/macho64.c",
    "ryzova/compat/macos/macho64.h",
    "ryzova/compat/macos/macho64_probe.c",
    "tests/test_phase5_7_macho.py",
    ".github/workflows/phase5-macho.yml",
)
SCHEMA = "ryzova-compact-macos-m0/v1"
LIMITS = {
    "input_bytes": 4 * 1024 * 1024,
    "load_commands": 32,
    "segments": 16,
    "segment_virtual_bytes": 64 * 1024 * 1024,
    "lowest_user_address": 65536,
    "exclusive_user_address_ceiling": "0x0000800000000000",
}
LOAD_COMMANDS = [
    "LC_SEGMENT_64", "LC_MAIN", "LC_UUID",
    "LC_BUILD_VERSION", "LC_VERSION_MIN_MACOSX",
]
CAPABILITIES = (
    "native_rz_guest_execution", "macho_loader_and_mapping",
    "darwin_bsd_syscalls", "mach_ipc", "dyld_and_dylib_resolution",
    "objective_c_runtime", "foundation_or_appkit", "gui_or_metal",
    "apple_silicon_arm64", "production_macos_app_compatibility",
)
AUTHORITY = (
    "host_syscall_forwarding", "host_filesystem_access",
    "privilege_escalation", "implicit_mounts", "code_signing_bypass",
    "apple_binary_or_sdk_redistribution",
)


def validate_contract(contract):
    if not isinstance(contract, dict):
        raise ValueError("MAC-0 contract must be an object")
    if (contract.get("schema") != SCHEMA or contract.get("phase") != "MAC-0"
            or contract.get("profile") != "intel-macho64-static-metadata-v1"
            or contract.get("target_architecture") != "x86_64"
            or contract.get("cpu_subtype") != "CPU_SUBTYPE_X86_64_ALL"
            or contract.get("supported_image") != "MH_EXECUTE (non-PIE, no dynamic libraries)"
            or contract.get("load_command_allowlist") != LOAD_COMMANDS
            or contract.get("bounded_limits") != LIMITS):
        raise ValueError("MAC-0 immutable research profile mismatch")
    caps = contract.get("capabilities")
    perms = contract.get("authority")
    if (not isinstance(caps, dict) or set(caps) != set(CAPABILITIES) | {
            "static_macho_metadata_validation"}
            or caps.get("static_macho_metadata_validation") is not True
            or any(caps.get(k) is not False for k in CAPABILITIES)
            or not isinstance(perms, dict) or set(perms) != set(AUTHORITY)
            or any(perms.get(k) is not False for k in AUTHORITY)):
        raise ValueError("unverified runtime capability or authority assertion")
    if not isinstance(contract.get("completion_policy"), str) or not contract["completion_policy"]:
        raise ValueError("missing explicit completion boundaries")
    return True


def inspect(root, contract=None):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("repository directory missing")
    contract_path = root / CONTRACT
    if not contract_path.is_file() or contract_path.is_symlink():
        raise ValueError("contract missing or symlinked")
    if contract is None:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    validate_contract(contract)
    result = {}
    for name in (CONTRACT, *SOURCES):
        path = root / name
        # Symlink denial also prevents future audit of redirected source text.
        if not path.is_file() or path.is_symlink():
            raise ValueError("missing or redirected source: " + name)
        data = path.read_bytes()
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("oversize audit source: " + name)
        if name.endswith((".c", ".h", ".py")) and not data.startswith(
                (b"/* SPDX-License-Identifier: AGPL-3.0-only */",
                 b"# SPDX-License-Identifier: AGPL-3.0-only")):
            raise ValueError("missing source SPDX identifier: " + name)
        result[name] = hashlib.sha256(data).hexdigest()
    return {
        "schema": "ryzova-compact-macos-m0-audit/v1",
        "phase": "MAC-0",
        "source_sha256": result,
        "static_contract_accepted": True,
        "application_execution_verified": False,
        "native_kernel_guest_execution_verified": False,
        "production_release_allowed": False,
        "mac1_to_mac7_completed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = inspect(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({"phase": "MAC-0", "files": len(evidence["source_sha256"]),
                      "runtime_verified": False, "release_allowed": False},
                     sort_keys=True))


if __name__ == "__main__":
    main()
