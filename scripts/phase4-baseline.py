#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 4.0: verify frozen baseline or prepare a NON-DESTRUCTIVE local recovery ref.

Never resets main, force-pushes, downloads drivers, or updates upstream/front.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ryzova/baselines/amd64-phase4.0.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
KERNEL_INPUTS = (
    "sys/src/9/",
    "sys/include/",
    "amd64/include/",
    "ryzova/",
    "scripts/phase3-native-build.py",
    "scripts/extract-9pc64.py",
    "scripts/check-identity.py",
    "scripts/verify-foundation.sh",
    ".github/workflows/phase3-native-build.yml",
)


def git(*args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def is_kernel_input(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix) for prefix in KERNEL_INPUTS)


def validate_branch_name(name: str) -> bool:
    return bool(re.fullmatch(r"recovery/[A-Za-z0-9][A-Za-z0-9._/-]{0,80}", name)) and not (
        ".." in name or name.endswith("/") or name.endswith(".lock") or "//" in name
    )


def manifest() -> dict:
    obj = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if obj.get("schema") != 1:
        raise RuntimeError("unsupported baseline schema")
    for key in ("baseline_commit", "last_verified_native_build_commit"):
        if not SHA.fullmatch(obj.get(key, "")):
            raise RuntimeError(f"invalid {key}")
    if not isinstance(obj.get("source_trees"), dict) or not obj["source_trees"]:
        raise RuntimeError("baseline source tree hashes missing")
    return obj


def verify() -> dict:
    info = manifest()
    baseline = info["baseline_commit"]
    source_verified = info["last_verified_native_build_commit"]
    # Verify baseline history, rather than trusting a mutable branch name.
    for commit in (baseline, source_verified):
        git("cat-file", "-e", f"{commit}^{{commit}}")
    if git("merge-base", "--is-ancestor", source_verified, baseline, check=False) != "":
        pass  # this command produces no stdout even when it fails; check below.
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_verified, baseline],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode != 0:
        raise RuntimeError("verified source commit is not an ancestor of baseline")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", baseline, "HEAD"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode != 0:
        raise RuntimeError("baseline is not in current integration history")
    checked = {}
    for path, expected in info["source_trees"].items():
        if not SHA.fullmatch(expected):
            raise RuntimeError(f"invalid expected tree SHA for {path}")
        actual = git("rev-parse", f"{baseline}:{path}")
        if actual != expected:
            raise RuntimeError(f"pinned baseline tree changed: {path}")
        checked[path] = actual
    known = git("show-ref", "--verify", f"refs/heads/{info['baseline_branch']}", check=False)
    if known:
        actual_branch = git("rev-parse", f"refs/heads/{info['baseline_branch']}")
        if actual_branch != baseline:
            raise RuntimeError("known-good baseline branch diverged from pinned commit")
    if (ROOT / ".github/workflows/sync-9front.yml").exists():
        raise RuntimeError("retired 9front sync workflow must not return")
    for file in (ROOT / ".github/workflows").glob("*.y*ml"):
        content = file.read_text(encoding="utf-8")
        if re.search(r"(?m)^\s*schedule\s*:", content):
            raise RuntimeError(f"unexpected schedule in {file.name}; review for hidden sync")
        if re.search(r"git\s+(?:fetch|push)[^\n]*(?:9front/9front|upstream/front|ninefront)", content):
            raise RuntimeError(f"9front auto-fetch/push detected in {file.name}")
    changed = [x for x in git("diff", "--name-only", f"{baseline}..HEAD").splitlines() if x]
    kernel_changes = [x for x in changed if is_kernel_input(x)]
    result = {
        "baseline_commit": baseline,
        "current_commit": git("rev-parse", "HEAD"),
        "last_verified_native_build_commit": source_verified,
        "baseline_trees_verified": checked,
        "baseline_branch_present": bool(known),
        "automatic_9front_sync_absent": True,
        "changed_files_since_baseline": changed,
        "kernel_or_build_input_changes": kernel_changes,
        "requires_new_native_qemu_test": bool(kernel_changes),
        "hardware_certified": False,
        "production_release_authorized": False,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "prepare-rollback"))
    parser.add_argument("--output", default="artifacts/phase4/baseline-check.json")
    parser.add_argument("--name", default="recovery/phase4-amd64-local")
    parser.add_argument("--create-local-branch", action="store_true")
    args = parser.parse_args()
    result = verify()
    path = ROOT / args.output
    path.parent.mkdir(parents=True, exist_ok=True)
    if args.command == "prepare-rollback":
        if not validate_branch_name(args.name):
            raise RuntimeError("recovery name must be a safe recovery/... branch")
        existing = git("show-ref", "--verify", f"refs/heads/{args.name}", check=False)
        if existing:
            raise RuntimeError("recovery branch already exists: refusing to overwrite")
        result["recovery_branch"] = args.name
        result["local_branch_created"] = False
        result["next_step"] = "Inspect baseline and create a PR with a reviewed revert; never force-reset main."
        if args.create_local_branch:
            git("branch", args.name, result["baseline_commit"])
            result["local_branch_created"] = True
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS: baseline source trees, provenance and no-auto-sync policy validated.")
    print(f"Baseline: {result['baseline_commit']}")
    print(f"Changed files: {len(result['changed_files_since_baseline'])}")
    print(f"Kernel/build-input changes: {len(result['kernel_or_build_input_changes'])}")
    print(f"QEMU rebuild required for changes: {result['requires_new_native_qemu_test']}")
    if args.command == "prepare-rollback":
        print(f"Recovery {args.name}: {'local branch created' if result['local_branch_created'] else 'dry-run only'}")
    print("Neither this tool nor the rollback branch performs remote changes or deployment.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
