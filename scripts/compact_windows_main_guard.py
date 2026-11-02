# SPDX-License-Identifier: AGPL-3.0-only
"""Strict, opt-in W1-W6 main integration boundary. NOT a release certification.

The single main PR must consist of independently engineered Windows
compatibility additions. Full release gates remain pending even when the
finite source-built AMD64/QEMU and virtio-SCSI profile passes.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
ALLOWED_PREFIXES=(
    "ryzova/compat/windows/",
    "scripts/compact_windows",
    "tests/test_compact_windows",
    "tests/fixtures/windows_w",
    "docs/COMPACT-WINDOWS",
    "docs/validation/compact-windows",
    ".github/workflows/compact-windows-",
)
ALLOWED_PATHS={"ryzova/compact/windows-v1-plan.json"}


def allowed(path):
    return isinstance(path,str) and bool(path) and (
        path in ALLOWED_PATHS or any(path.startswith(p) for p in ALLOWED_PREFIXES)
    ) and ".." not in path.split("/")


def validate_plan(plan):
    if not isinstance(plan,dict) or plan.get("schema")!="compact-windows-plan/v1":
        raise ValueError("unexpected source plan")
    if [p["id"] for p in plan.get("phases",[])]!=[
        "W1","W2","W3","W4","W5","W6"
    ]:
        raise ValueError("incomplete Windows phase lineage")
    states=[r.get("state") for r in plan.get("requirements",[])]
    if len(states)!=7 or any(x!="pending" for x in states):
        raise ValueError("full-release requirements falsely satisfied")
    if plan.get("windows_execution_qualified") is not False:
        raise ValueError("unqualified general Windows execution advertised")
    if plan.get("general_windows_compatibility_claim") is not False:
        raise ValueError("unsupported general compatibility claim")
    if plan.get("native_amd64_qemu_profile_qualified") is not True:
        raise ValueError("bounded source-built native profile absent")
    q=plan.get("w6_qualification",{})
    if (q.get("bounded_native_phase_complete") is not True
        or q.get("full_phase_complete") is not False
        or q.get("physical_hardware")!="not-tested"
        or q.get("arm64_windows")!="not-tested"
        or q.get("boot_hjfs_sigkill_persistence")!="not-qualified"):
        raise ValueError("W6 bounded/full release boundary violated")
    return True


def validate_paths(paths):
    if not paths or any(not allowed(x) for x in paths):
        raise ValueError("non-Windows source/driver/kernel/sync changed")
    return True


def main():
    base=os.environ.get("GITHUB_BASE_REF","main")
    if base!="main":
        raise ValueError("main integration must target main")
    proc=subprocess.run(["git","merge-base","origin/main","HEAD"],
        cwd=ROOT,check=True,text=True,capture_output=True)
    ancestor=proc.stdout.strip()
    diff=subprocess.run(["git","diff","--name-only",ancestor,"HEAD"],
        cwd=ROOT,check=True,text=True,capture_output=True)
    files=[x for x in diff.stdout.splitlines() if x]
    validate_paths(files)
    plan=json.loads((ROOT/"ryzova/compact/windows-v1-plan.json").read_text())
    validate_plan(plan)
    print(json.dumps({
        "schema":"compact-windows-main-integration-guard/v1",
        "target_base":"main",
        "modified_files":len(files),
        "driver_linux_9front_sync_touched":False,
        "bounded_amd64_qemu_profile":True,
        "full_release_qualified":False,
        "arm64_windows_qualified":False,
        "hardware_power_loss_qualified":False,
    },sort_keys=True))


if __name__=="__main__":
    try:
        main()
    except (OSError,ValueError,subprocess.CalledProcessError) as error:
        print(f"FAIL CLOSED: {error}",file=sys.stderr)
        raise SystemExit(1)
