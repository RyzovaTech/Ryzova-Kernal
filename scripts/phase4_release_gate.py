#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed evidence inventory for kernel release candidacy; never publishes."""
import argparse
import json
import pathlib
import re
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
SHA256=re.compile(r"^[0-9a-f]{64}$")
GITSHA=re.compile(r"^[0-9a-f]{40}$")
def document(root, path):
    return json.loads((root/path).read_text(encoding="utf-8"))
def digest(v, pattern=SHA256):
    return isinstance(v,str) and bool(pattern.fullmatch(v))
def approval(v, scoped=False):
    return isinstance(v,dict) and v.get("approved") is True and (
        not scoped or v.get("artifact_scoped") is True
    ) and isinstance(v.get("review_reference"),str) and bool(v["review_reference"].strip())
def assess(root=ROOT):
    draft=document(root,"ryzova/release/amd64-preview-candidate.json")
    kernel=document(root,"ryzova/metadata/kernel-version.json")
    profile=document(root,"ryzova/config/amd64-developer.json")
    sdk=document(root,"ryzova/sdk/kernel-contract.json")
    physical=document(root,"ryzova/drivers/physical-tests.json")
    rights=draft.get("rights_clearance",{})
    rep=draft.get("independent_reproduction",{})
    sec=draft.get("security_qualification",{})
    sign=draft.get("signing",{})
    records=physical.get("test_records",[])
    checks={
        "metadata_consistent": draft.get("schema")=="ryzova-release-candidate/v1"
          and draft.get("architecture")==profile.get("architecture")==sdk.get("architecture")=="amd64"
          and draft.get("version")==kernel.get("version")
          and draft.get("abi")==kernel.get("abi")==sdk.get("abi")=="experimental-0",
        "pinned_builder_profile": digest(profile.get("guest_image_sha256"))
          and profile.get("build_system")=="9front-mk" and profile.get("release_ready") is False,
        "no_upstream_auto_sync": not (root/".github/workflows/sync-9front.yml").exists(),
        "artifact_sha256_recorded": digest(draft.get("kernel_artifact_sha256")),
        "exact_source_commit_recorded": digest(draft.get("source_commit"), GITSHA),
        "scoped_redistribution_rights": approval(rights, scoped=True),
        "physical_qualification": isinstance(records,list) and len(records)>0
          and physical.get("license_clearance") is True
          and isinstance(physical.get("maintainer_approval"),str)
          and bool(physical.get("maintainer_approval")),
        "independent_reproduction": isinstance(rep,dict) and rep.get("verified") is True
          and digest(rep.get("log_sha256")) and bool(rep.get("review_reference")),
        "security_review": isinstance(sec,dict) and sec.get("reviewed") is True
          and digest(sec.get("soak_log_sha256")) and digest(sec.get("fuzz_log_sha256"))
          and bool(sec.get("review_reference")),
        "maintainer_authorization": approval(draft.get("maintainer_approval",{})),
        "signature_review": isinstance(sign,dict) and sign.get("verified") is True
          and bool(sign.get("signature_reference")),
        "not_already_published": draft.get("published") is False
    }
    return {
        "schema":"ryzova-phase4-release-evidence/v1",
        "checks":checks,
        "candidate_eligible":all(checks.values()),
        "publication_permitted_by_ci":False,
        "missing":[k for k,v in checks.items() if not v],
        "warning":"This is a metadata checklist only; human authentication of evidence and signature is required. Never publish from this script.",
    }
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",default="artifacts/phase4/release-evidence.json")
    p.add_argument("--enforce-release",action="store_true")
    opt=p.parse_args()
    result=assess()
    output=ROOT/opt.output
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"candidate_eligible":result["candidate_eligible"],"missing":result["missing"]},indent=2))
    if opt.enforce_release:
        print("BLOCKED: publication requires separate authorized, legally reviewed process.",file=sys.stderr)
        return 2
    return 0
if __name__=="__main__":
    sys.exit(main())
