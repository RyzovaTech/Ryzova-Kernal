#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 5.9 acceptance of experimental source only; never release an OS image."""
import argparse
import hashlib
import json
from pathlib import Path

from phase5_matrix import review as compatibility_review
from phase4_release_gate import assess as release_review

ROOT=Path(__file__).resolve().parents[1]
REQUIRED={
    "acceptance_manifest":"ryzova/compat/phase5-9-acceptance.json",
    "phase5_status":"ryzova/compat/phase5-status.json",
    "phase5_matrix":"scripts/phase5_matrix.py",
    "linux_elf":"ryzova/compat/linux/elf64.c",
    "linux_process":"ryzova/compat/linux/syscall.c",
    "linux_namespace":"ryzova/compat/linux/namespace.c",
    "linux_host_interpreter":"ryzova/compat/linux/subset_vm.c",
    "windows_pe":"ryzova/compat/windows/pe64.c",
    "macos_macho":"ryzova/compat/macos/macho64.c",
    "security_tests":"tests/test_phase5_6_security.py",
    "final_tests":"tests/test_phase5_9_acceptance.py",
    "qemu_workflow":".github/workflows/phase3-native-build.yml",
    "closeout_workflow":".github/workflows/phase5-closeout.yml",
    "release_gate":"scripts/phase4_release_gate.py"
}
def inspect(root=ROOT, manifest=None, platform_review=None, release=None):
    if manifest is None:
        manifest=json.loads((root/REQUIRED["acceptance_manifest"]).read_text(encoding="utf-8"))
    if platform_review is None:
        platform_review=compatibility_review(root)
    if release is None:
        release=release_review(root)
    files={k:(root/p).is_file() for k,p in REQUIRED.items()}
    checks={
        "phase5_0_to_5_8_foundations_green":platform_review.get("static_foundation_validated") is True,
        "all_required_sources_present":all(files.values()),
        "acceptance_schema":manifest.get("schema")=="ryzova-phase5-9-acceptance/v1",
        "experimental_only":manifest.get("completion_scope")=="experimental-cross-platform-source-foundations"
          and manifest.get("source_only_review") is True,
        "explicit_source_merge_requested":manifest.get("source_merge_requested_by_user") is True
          and manifest.get("source_merge_requires_all_ci_green") is True,
        "host_linux_interpreter_prototype":manifest.get("linux_host_interpreter_verified") is True,
        "no_native_linux_execution_claim":manifest.get("linux_native_ryzova_app_execution_verified") is False
          and platform_review.get("kernel_linux_application_executed") is False,
        "no_windows_execution_claim":manifest.get("windows_application_execution_verified") is False
          and platform_review.get("windows_application_executed") is False,
        "no_macos_execution_claim":manifest.get("macos_application_execution_verified") is False
          and platform_review.get("macos_application_executed") is False,
        "no_runtime_mount_claim":manifest.get("runtime_namespaces_kernel_mounted") is False,
        "no_production_compatibility_claim":manifest.get("production_compatibility_complete") is False,
        "release_remains_blocked":manifest.get("public_binary_release_authorized") is False
          and release.get("candidate_eligible") is False
          and release.get("publication_permitted_by_ci") is False,
        "research_handoff_only":manifest.get("phase6_research_entry_allowed") is True,
        "upstream_sync_remains_disabled":not (root/".github/workflows/sync-9front.yml").exists(),
    }
    sha256={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in REQUIRED.values()
            if (root/p).is_file()}
    return {
        "schema":"ryzova-phase5-9-final-evidence/v1",
        "checks":checks,
        "experimental_source_foundation_acceptance":all(checks.values()),
        "merge_into_main_requires_external_git_ci_verification":True,
        "product_compatibility_verified":False,
        "linux_app_executed_in_native_ryzova_kernel":False,
        "windows_app_execution_verified":False,
        "macos_app_execution_verified":False,
        "public_release_approved":False,
        "phase6_research_ready":all(checks.values()),
        "evidence":"Host GCC/Clang compatibility tests + separate fresh native build/QEMU CI must be green for the same exact git commit",
        "remaining":manifest.get("remaining",[]),
        "file_sha256":sha256,
        "warning":"Source-only integration is not a Linux/Windows/macOS application support announcement."
    }
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",default="artifacts/phase5/phase5-9-acceptance.json")
    opts=p.parse_args()
    report=inspect()
    target=ROOT/opts.output
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"checks":report["checks"],
                      "experimental_source_foundation_acceptance":report["experimental_source_foundation_acceptance"],
                      "product_compatibility_verified":report["product_compatibility_verified"]},indent=2))
    return 0 if report["experimental_source_foundation_acceptance"] else 1
if __name__=="__main__":
    raise SystemExit(main())
