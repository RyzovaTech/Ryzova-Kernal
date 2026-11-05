# SPDX-License-Identifier: AGPL-3.0-only
"""W8 real Windows System32 console app reference/inventory, NEVER Ryzova launch.

Only named, genuine Microsoft Windows console binaries execute on the hosted
Windows reference runner. Windows executables are not copied or distributed.
Direct imports are reported as compatibility evidence, NOT guest execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

from compact_windows_import_audit import FILE_LIMIT, discover

SCHEMA = "compact-windows-real-app-reference/v1"
APPLICATIONS = (
    ("sort", "sort.exe", (), b"orange\r\napple\r\n"),
    ("findstr", "findstr.exe", ("/B", "/L", "apple"), b"apple\r\nbanana\r\napplesauce\r\n"),
    ("where", "where.exe", ("cmd.exe",), b""),
)
MAX_OUTPUT = 16384


def verify_reference(name, result):
    if type(result.returncode) is not int or result.returncode != 0:
        raise ValueError("Windows reference command failed: " + name)
    if (type(result.stdout) is not bytes or len(result.stdout) > MAX_OUTPUT or
            b"\0" in result.stdout or type(result.stderr) is not bytes or
            len(result.stderr) > MAX_OUTPUT):
        raise ValueError("invalid or oversized Windows reference output")
    lines = result.stdout.replace(b"\r\n", b"\n").splitlines()
    if name == "sort":
        valid = lines == [b"apple", b"orange"]
    elif name == "findstr":
        valid = lines == [b"apple", b"applesauce"]
    elif name == "where":
        valid = (1 <= len(lines) <= 4 and
                 all(re.fullmatch(rb"[A-Za-z]:\\[^\r\n\0]+\\cmd\.exe", x, re.I)
                     for x in lines))
    else:
        raise ValueError("unknown Windows reference application")
    if not valid:
        raise ValueError("Windows reference output mismatch: " + name)
    return {
        "reference_passed": True, "exit_code": 0,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def analyze(name, binary, plan, receipt):
    if name not in {x[0] for x in APPLICATIONS} or type(binary) is not bytes:
        raise ValueError("unrecognized Windows reference application")
    if not 256 <= len(binary) <= FILE_LIMIT:
        raise ValueError("reference PE size outside bounded input")
    if type(receipt) is not dict or receipt.get("reference_passed") is not True:
        raise ValueError("unverified Windows reference receipt")
    record = {
        "name": name, "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "binary_bytes": len(binary), "windows_reference": receipt,
        "pe_import_audit": None, "pe_audit_rejection": None,
        "guest_execution_verified": False, "transitive_dll_closure_verified": False,
        "application_workflow_qualified": False,
    }
    try:
        audit = discover(binary, plan)
        if audit["architecture"] != "amd64":
            raise ValueError("Windows reference executable not AMD64")
        record["pe_import_audit"] = audit
    except ValueError as exc:
        # An unsupported import table is a blocker, not a successful scan.
        record["pe_audit_rejection"] = str(exc)[:256]
    record["blocking_reasons"] = [
        "Native Ryzova execution of this named Windows app not demonstrated",
        "Transitive DLL imports and Windows runtime behaviour not qualified",
    ]
    if record["pe_audit_rejection"] is not None:
        record["blocking_reasons"].append("PE import parser could not qualify binary")
    elif not record["pe_import_audit"]["declared_import_profile_covered"]:
        record["blocking_reasons"].append("Declared direct import/runtime profile incomplete")
    return record


def collect(plan, *, system_root=None, runner_version=None, commit=None):
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("real Windows AMD64 reference runner required")
    system_root = system_root or os.environ.get("SystemRoot")
    if not system_root:
        raise RuntimeError("trusted Windows SystemRoot required")
    base = (Path(system_root).resolve() / "System32").resolve()
    if not base.is_dir():
        raise RuntimeError("missing Windows System32")
    results = []
    for name, filename, arguments, stdin in APPLICATIONS:
        path = base / filename
        if (not path.is_file() or path.is_symlink() or
                path.resolve().parent != base or path.stat().st_size > FILE_LIMIT):
            raise RuntimeError("invalid local Windows System32 app: " + name)
        binary = path.read_bytes()
        # Absolute System32 path, fixed benign argv/stdin, never shell=True.
        outcome = subprocess.run([str(path), *arguments], input=stdin,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=12, check=False)
        results.append(analyze(name, binary, plan, verify_reference(name, outcome)))
    return {
        "schema": SCHEMA,
        "reference_os": "Windows AMD64 hosted reference, NOT Ryzova",
        "windows_os_version": platform.version(),
        "runner_image_version": runner_version or "unrecorded",
        "source_commit": commit or "unrecorded",
        "reference_applications": results,
        "windows_reference_passed": len(results) == len(APPLICATIONS),
        "native_guest_execution_qualified": False,
        "windows_v1_release_qualified": False,
        "limitations": [
            "Microsoft System32 PE binaries not stored in artifacts",
            "Hosted OS image is mutable; binaries SHA256 pinned per run only",
            "Import inventory does not establish transitive DLL closure",
            "Windows host output cannot substitute for native Ryzova guest execution",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=Path(__file__).resolve().parents[1] /
                        "ryzova/compact/windows-v1-plan.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    report = collect(plan, runner_version=os.environ.get("ImageVersion"),
                     commit=os.environ.get("RYZOVA_SOURCE_SHA") or os.environ.get("GITHUB_SHA"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "reference_apps": len(report["reference_applications"]),
        "reference_passed": report["windows_reference_passed"],
        "declared_profile_covered": sum(
            bool(x["pe_import_audit"] and
                 x["pe_import_audit"]["declared_import_profile_covered"])
            for x in report["reference_applications"]),
        "native_guest_execution_qualified": False,
        "windows_v1_release_qualified": False,
    }, sort_keys=True))
    # Bounded, privacy-safe logs: allow downstream engineers to prioritize
    # actual unsupported imports without downloading proprietary PE binaries.
    for item in report["reference_applications"]:
        audit = item["pe_import_audit"]
        missing = audit["missing_or_ordinal_imports"] if audit else []
        print("W8_REAL_APP_IMPORTS " + json.dumps({
            "name": item["name"],
            "pe_sha256": item["binary_sha256"],
            "pe_bytes": item["binary_bytes"],
            "parser_rejection": item["pe_audit_rejection"],
            "direct_imports": audit["direct_imports"] if audit else None,
            "missing_direct_count": len(missing),
            "missing_direct_sample": missing[:24],
            "import_modules": audit["modules"] if audit else [],
            "guest_execution_verified": False,
        }, sort_keys=True))
