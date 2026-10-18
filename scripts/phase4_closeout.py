#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 4 static closeout; runtime native QEMU verification remains separate CI."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from phase4_integrity import evaluate as integration
from phase4_release_gate import assess as release_assessment
from phase4_variant_gate import validate

ROOT=Path(__file__).resolve().parents[1]
FILES = {
  "4.0": ["ryzova/baselines/amd64-phase4.0.json",
          "scripts/phase4-baseline.py",".github/workflows/phase4-baseline.yml"],
  "4.1": ["scripts/phase4_1_stability.py","tests/test_phase4_1_stability.py"],
  "4.2": ["scripts/driver_release_matrix.py",
          ".github/workflows/driver-release-gates.yml"],
  "4.3": ["ryzova/config/amd64-developer.json",
          "scripts/phase4_provenance.py"],
  "4.4": ["ryzova/sdk/kernel-contract.json",
          "scripts/phase4_variant_gate.py"],
  "4.5": ["scripts/phase4_5_stress.py","tests/test_phase4_5_stress.py",
          ".github/workflows/phase3-native-build.yml"],
  "4.6": ["ryzova/drivers/physical-tests.json",
          "scripts/phase4_release_gate.py"],
  "4.7": ["scripts/phase4_provenance.py"],
  "4.8": ["ryzova/sdk/examples/amd64-minimal-variant.json"],
  "4.9": ["ryzova/release/amd64-preview-candidate.json",
          ".github/workflows/phase4-release-readiness.yml"],
}
def evaluate(run_baseline=True):
    integration_report=integration()
    release=release_assessment()
    contract=json.loads((ROOT/"ryzova/sdk/kernel-contract.json").read_text())
    variant=json.loads((ROOT/"ryzova/sdk/examples/amd64-minimal-variant.json").read_text())
    variants=validate(variant,contract)
    present={p:all((ROOT/f).is_file() for f in paths) for p,paths in FILES.items()}
    baseline=None
    if run_baseline:
        test=subprocess.run([sys.executable,str(ROOT/"scripts/phase4-baseline.py"),"verify"],
                            cwd=ROOT,text=True,capture_output=True,timeout=120)
        baseline={"passed":test.returncode==0,"exit_code":test.returncode,
                  "output_tail":(test.stdout+"\n"+test.stderr)[-1200:]}
    checks={
      "all_phase_component_files_present":all(present.values()),
      "phase4_integration_passed":integration_report["pass"],
      "experimental_variant_schema_consistent":variants["schema_compatible"],
      "automatic_9front_sync_disabled":integration_report["checks"]["upstream_auto_sync_absent"],
      "public_release_is_blocked":release["candidate_eligible"] is False
          and release["publication_permitted_by_ci"] is False,
    }
    if run_baseline: checks["frozen_baseline_verified"]=baseline["passed"]
    return {
      "schema":"ryzova-phase4-closeout/v1",
      "checks":checks,
      "stage_files_present":present,
      "engineering_infrastructure_passed":all(checks.values()),
      "phase5_experimental_planning_allowed":all(checks.values()),
      "phase5_compatibility_implemented":False,
      "phase4_production_qualification":False,
      "public_release_permitted":False,
      "native_qemu_build_status":"must_pass_separate_phase3-native-build_workflow_for_exact_commit",
      "baseline":baseline,
      "release_blockers":release["missing"],
      "unverified":["physical hardware qualification","long-duration soak and memory failure injection",
                    "independent security audit and kernel fuzzing",
                    "cross-host binary reproducibility","stable ABI",
                    "artifact-specific rights clearance","signed public release"],
      "notice":"Engineering closeout validates on-repository gates only. QEMU CI is separate. Phase 5 may begin experimental research, not deployment."
    }
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",default="artifacts/phase4/final-closeout.json")
    args=ap.parse_args()
    report=evaluate()
    destination=ROOT/args.output
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"checks":report["checks"],
                      "phase5_experimental_planning_allowed":report["phase5_experimental_planning_allowed"],
                      "public_release_permitted":report["public_release_permitted"]},indent=2))
    return 0 if report["engineering_infrastructure_passed"] else 1
if __name__=="__main__":
    sys.exit(main())
