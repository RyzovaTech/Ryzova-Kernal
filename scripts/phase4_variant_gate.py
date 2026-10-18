#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Inspect downstream OS variant metadata against current experimental ABI."""
import argparse
import json
import pathlib
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
def validate(profile, contract):
    expected=contract.get("native_interfaces",[])
    checks={
      "schema":profile.get("schema")=="ryzova-variant-profile/v1",
      "amd64":profile.get("architecture")==contract.get("architecture")=="amd64",
      "experimental_abi":profile.get("kernel_abi")==contract.get("abi")=="experimental-0",
      "declared_native_interfaces":set(profile.get("interfaces",[]))==set(expected),
      "no_unsupported_binary_compatibility":all(profile.get(k) is False for k in
          ("linux_binary_compatibility","windows_binary_compatibility","macos_binary_compatibility")),
      "no_unverified_distribution_claim":profile.get("redistributable") is False
          and profile.get("boot_tested") is False,
    }
    return {"schema":"ryzova-variant-validation/v1","checks":checks,
      "schema_compatible":all(checks.values()),"boot_qualified":False,"redistribution_approved":False,
      "warning":"Contract/schema compatibility is not proof the OS boots or can be distributed."}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="ryzova/sdk/examples/amd64-minimal-variant.json")
    p.add_argument("--output",default="artifacts/phase4/variant-validation.json")
    a=p.parse_args()
    contract=json.loads((ROOT/"ryzova/sdk/kernel-contract.json").read_text())
    profile=json.loads((ROOT/a.input).read_text())
    result=validate(profile,contract)
    output=ROOT/a.output;output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result["checks"],indent=2))
    return 0 if result["schema_compatible"] else 1
if __name__=="__main__":
    sys.exit(main())
