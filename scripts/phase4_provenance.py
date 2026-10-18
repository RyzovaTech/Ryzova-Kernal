#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate provenance of input trees and builder pin, NOT bitwise build reproducibility."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

ROOT=pathlib.Path(__file__).resolve().parents[1]
SUBTREES=("sys/src/9","sys/include","amd64/include")
def git(*args, root=ROOT):
    return subprocess.check_output(["git",*args],cwd=root,text=True).strip()
def collect(root=ROOT):
    profile=json.loads((root/"ryzova/config/amd64-developer.json").read_text())
    sha=git("rev-parse","HEAD",root=root)
    trees={p:git("rev-parse",f"HEAD:{p}",root=root) for p in SUBTREES}
    pin=profile["guest_image_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}",pin):raise ValueError("invalid builder sha256")
    return {"schema":"ryzova-phase4-build-provenance/v1","source_commit":sha,
        "source_trees":trees,"guest_image_url":profile["guest_image_url"],
        "guest_image_sha256":pin,"toolchain":profile["build_system"],
        "input_profile_sha256":hashlib.sha256((root/"ryzova/config/amd64-developer.json").read_bytes()).hexdigest(),
        "binary_reproducible_across_build_hosts":False,
        "notes":"Git source tree IDs and pinned inputs are provenance only; independent binary comparisons still required."}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",default="artifacts/phase4/build-provenance.json")
    a=p.parse_args()
    output=ROOT/a.output;output.parent.mkdir(parents=True,exist_ok=True)
    report=collect()
    output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"source_commit":report["source_commit"],
                      "source_trees":report["source_trees"]},indent=2))
if __name__=="__main__":
    main()
