#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.0–6.5 source acceptance; NOT certification of remote resources."""
import argparse
import hashlib
import json
from pathlib import Path
from phase6_status import check as first_stages
from phase4_release_gate import assess as release_assess

ROOT=Path(__file__).resolve().parents[1]
REQUIRED=(
    "ryzova/remote/trust.py",
    "ryzova/remote/p9.py",
    "ryzova/remote/cache.py",
    "ryzova/remote/compute.py",
    "ryzova/remote/recovery.py",
    "ryzova/remote/tlsloop.py",
    "tests/test_phase6_4_recovery.py",
    "tests/test_phase6_5_tls.py",
    ".github/workflows/phase6-remote.yml",
    ".github/workflows/phase6-closeout.yml",
    "docs/PHASE6-4-RECOVERY.md",
    "docs/PHASE6-5-TLS-QEMU.md",
    "ryzova/remote/phase6-closeout.json"
)
def inspect(root=ROOT, manifest=None, prior=None, release=None):
    if manifest is None:
        manifest=json.loads((root/"ryzova/remote/phase6-closeout.json").read_text())
    if prior is None: prior=first_stages(root)
    if release is None: release=release_assess(root)
    checks={
        "all_stage_files_present":all((root/p).is_file() for p in REQUIRED),
        "experimental_host_scope":manifest.get("schema")=="ryzova-phase6-0-5-closeout/v1"
            and manifest.get("completion_scope")=="host-loopback-research-prototypes-only",
        "phase6_0_to_6_3_previous_gates":prior.get("host_prototype_foundation_valid") is True,
        "source_only_merge_request":manifest.get("source_merge_requested_by_user") is True
            and manifest.get("source_merge_requires_all_ci_green") is True,
        "default_disabled":manifest.get("default_enabled") is False,
        "tls_network_loopback_evidence":manifest.get("tls13_mutual_leaf_certificate_localhost_tested") is True
            and manifest.get("actual_tcp_loopback_tested") is True,
        "scoped_9p_data_compute_prototypes":all(manifest.get(k) is True for k in
            ("read_only_9p2000_wire_tested","pinned_public_data_cache_tested",
             "allowlisted_pure_task_delegation_tested","circuit_breaker_and_telemetry_tested")),
        "no_unverified_remote_machine_claim":manifest.get("remote_machine_access_verified") is False,
        "no_native_9p_kernel_mount_claim":manifest.get("native_ryzova_9p_mount_verified") is False,
        "not_physical_ram_or_cpu":manifest.get("remote_kernel_ram_verified") is False
            and manifest.get("additional_cpu_cores_verified") is False,
        "no_certified_production_key_management":manifest.get("production_tls_key_management_verified") is False,
        "public_release_blocked":manifest.get("public_release_authorized") is False
            and release.get("candidate_eligible") is False
            and release.get("publication_permitted_by_ci") is False,
        "no_upstream_sync":not (root/".github/workflows/sync-9front.yml").exists(),
    }
    return {
      "schema":"ryzova-phase6-research-integration-evidence/v1",
      "checks":checks,
      "experimental_source_acceptable":all(checks.values()),
      "merge_requires_exact_head_green_git_ci":True,
      "native_ryzova_remote_resources_working":False,
      "public_binary_release_permitted":False,
      "kernel_qemu_test_scope":"kernel boot/source compilation regressions only; TLS service runs on CI Linux host",
      "file_sha256":{p:hashlib.sha256((root/p).read_bytes()).hexdigest()
                     for p in REQUIRED if (root/p).is_file()},
      "followups":manifest.get("limitations",[])
    }
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--output",default="artifacts/phase6/phase6-closeout.json")
    args=a.parse_args()
    out=ROOT/args.output
    result=inspect()
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"checks":result["checks"],"source_ok":result["experimental_source_acceptable"],
                      "native_resources_working":False},indent=2))
    return 0 if result["experimental_source_acceptable"] else 1
if __name__=="__main__":
    raise SystemExit(main())
