# SPDX-License-Identifier: AGPL-3.0-only
"""W8: fail-closed shortlist from real Windows reference PE import evidence.

Input is *only* the signed-off structure from the fixed System32 reference job.
No Windows executable/DLL is downloaded, copied, launched, or marked guest
compatible. A small import gap does NOT imply actual native Ryzova execution.
"""
import argparse
import json
from pathlib import Path
import re

SCHEMA = "compact-windows-w8-app-triage/v1"
INPUT_SCHEMA = "compact-windows-real-app-reference/v1"
NAMES = ("sort", "findstr", "where")
MAX_PE_INPUT = 4 * 1024 * 1024
MAX_DIRECT_IMPORTS = 32
MAX_IMPORT_MODULES = 4


def expected_text(value, label, *, limit=256):
    if type(value) is not str or not 1 <= len(value) <= limit:
        raise ValueError("untrusted " + label)
    return value


def require_sha(value, label):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError("bad digest: " + label)


def triage(report):
    if (type(report) is not dict or report.get("schema") != INPUT_SCHEMA or
            report.get("windows_reference_passed") is not True or
            report.get("native_guest_execution_qualified") is not False or
            report.get("windows_v1_release_qualified") is not False):
        raise ValueError("unqualified/inconsistent Windows host reference")
    expected_text(report.get("source_commit"), "source commit")
    if not re.fullmatch(r"[a-f0-9]{40}", report["source_commit"]):
        raise ValueError("missing exact source commit")
    expected_text(report.get("windows_os_version"), "Windows OS version")
    expected_text(report.get("runner_image_version"), "runner version")
    if report["runner_image_version"] == "unrecorded":
        raise ValueError("missing Windows runner provenance")
    apps = report.get("reference_applications")
    if (type(apps) is not list or len(apps) != len(NAMES) or
            set(x.get("name") for x in apps if type(x) is dict) != set(NAMES)):
        raise ValueError("missing, duplicated or unknown application names")
    records = []
    eligible = []
    for order, name in enumerate(NAMES):
        item = next(x for x in apps if x["name"] == name)
        binary_size = item.get("binary_bytes")
        if type(binary_size) is not int or not 256 <= binary_size <= 64*1024*1024:
            raise ValueError("invalid original PE size")
        require_sha(item.get("binary_sha256"), name + " PE")
        reference = item.get("windows_reference")
        if (type(reference) is not dict or
                reference.get("reference_passed") is not True or
                type(reference.get("exit_code")) is not int or
                reference["exit_code"] != 0 or
                type(reference.get("stdout_bytes")) is not int or
                not 0 <= reference["stdout_bytes"] <= 16384):
            raise ValueError("invalid real Windows execution evidence")
        for key in ("stdout_sha256", "stderr_sha256"):
            require_sha(reference.get(key), name + " " + key)
        if (item.get("guest_execution_verified") is not False or
                item.get("transitive_dll_closure_verified") is not False or
                item.get("application_workflow_qualified") is not False):
            raise ValueError("forged native Windows guest qualification")
        audit = item.get("pe_import_audit")
        rejection = item.get("pe_audit_rejection")
        if (rejection is not None and (type(rejection) is not str or
                                       not 1 <= len(rejection) <= 256)):
            raise ValueError("invalid PE rejection")
        if bool(audit is not None) == bool(rejection is not None):
            raise ValueError("ambiguous PE parser result")
        blockers = ["Native Ryzova guest execution not tested",
                    "Transitive Windows DLL/CRT, runtime and I/O semantics not qualified"]
        hard = False
        direct_count = None
        missing = []
        modules = []
        if binary_size > MAX_PE_INPUT:
            blockers.append("PE exceeds current 4-MiB native guest image cap")
            hard = True
        if rejection is not None:
            blockers.append("PE parser rejected input: " + rejection)
            hard = True
        else:
            if type(audit) is not dict or audit.get("architecture") != "amd64":
                raise ValueError("invalid PE architecture inventory")
            direct_count = audit.get("direct_imports")
            modules = audit.get("modules")
            missing = audit.get("missing_or_ordinal_imports")
            if (type(direct_count) is not int or not 0 <= direct_count <= 512 or
                    type(modules) is not list or len(modules) > 32 or
                    any(type(v) is not str for v in modules) or
                    type(missing) is not list or len(missing) > 512 or
                    any(type(v) is not str for v in missing)):
                raise ValueError("invalid PE import inventory bounds")
            if direct_count > MAX_DIRECT_IMPORTS:
                blockers.append("PE exceeds current 32-import native loader cap")
                hard = True
            if len(modules) > MAX_IMPORT_MODULES:
                blockers.append("PE exceeds current four-import-module boundary")
                hard = True
            if missing:
                blockers.append(str(len(missing)) + " direct imports need original Win32 implementations")
            if audit.get("delay_load_requires_runtime_resolver") is True or audit.get("delay_load_modules"):
                blockers.append("Unimplemented delay-load resolver")
                hard = True
            if audit.get("runtime_directories_unqualified"):
                blockers.append("Unqualified TLS/CLR directory")
                hard = True
        can_investigate = not hard
        record = {
            "name": name, "reference_binary_sha256": item["binary_sha256"],
            "reference_binary_bytes": binary_size, "direct_import_count": direct_count,
            "missing_direct_imports": sorted(missing),
            "import_modules": sorted(modules), "structurally_within_current_caps": can_investigate,
            "blockers": blockers, "guest_execution_verified": False,
            "transitive_dll_closure_verified": False,
            "application_workflow_qualified": False,
        }
        records.append(record)
        if can_investigate:
            eligible.append((len(missing), direct_count, binary_size, order, name))
    best = min(eligible)[-1] if eligible else None
    return {
        "schema": SCHEMA, "source_commit": report["source_commit"],
        "runner_image_version": report["runner_image_version"],
        "reference_os_version": report["windows_os_version"],
        "reference_app_count": len(NAMES),
        "candidate_for_engineering_only": best,
        "candidate_is_guest_qualified": False,
        "native_guest_execution_qualified": False,
        "windows_v1_release_qualified": False,
        "apps": records,
        "next_step": ("Study the exact candidate's missing APIs/CRT and execute the "
                      "same source-licensed PE under Ryzova native AMD64 QEMU"
                      if best is not None else
                      "None of the unmodified System32 PE images is within the current "
                      "bounded loader profile; choose a reviewed source-available app"),
        "limitations": [
            "Only three hosted Microsoft System32 references; proprietary binaries not copied",
            "Current PE loader limits, import count and modules do not prove actual PE admission",
            "Missing imports and transitive DLL closure require separately pinned execution tests",
            "Candidate selection never authorizes a Windows API or native release",
        ],
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reference", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    data = json.loads(args.reference.read_text(encoding="utf-8"))
    receipt = triage(data)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "selected_for_engineering_only": receipt["candidate_for_engineering_only"],
        "native_guest_execution_qualified": False,
        "windows_v1_release_qualified": False,
    }, sort_keys=True))
