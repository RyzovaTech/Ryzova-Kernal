#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Evaluate exact Phase 5 compatibility scope without claiming app support."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILES={
  "5.0":["docs/PHASE5-0-ARCHITECTURE.md"],
  "5.1":["ryzova/compat/linux/elf64.c","tests/test_phase5_elf.py"],
  "5.2":["ryzova/compat/linux/syscall.c","tests/test_phase5_runtime.py"],
  "5.3":["ryzova/compat/linux/namespace.c"],
  "5.4":["ryzova/compat/linux/subset_vm.c","tests/test_phase5_4.py"],
  "5.5":["ryzova/compat/windows/pe64.c","tests/test_phase5_5_pe.py"],
  "5.6":["tests/test_phase5_6_security.py",".github/workflows/phase5-security.yml"],
  "5.7":["ryzova/compat/macos/macho64.c","tests/test_phase5_7_macho.py"],
  "5.8":["ryzova/compat/phase5-status.json",".github/workflows/phase5-integration.yml"]
}
def review(root=ROOT, spec=None):
    if spec is None:
        spec=json.loads((root/"ryzova/compat/phase5-status.json").read_text())
    pl=spec.get("platforms",{})
    linux=pl.get("linux",{})
    win=pl.get("windows",{})
    mac=pl.get("macos",{})
    present={p:all((root/f).is_file() for f in paths) for p,paths in FILES.items()}
    checks={
      "source_foundations_present":all(present.values()),
      "schema_correct":spec.get("schema")=="ryzova-phase5-compatibility/v1",
      "still_experimental":spec.get("status")=="experimental-foundations-only",
      "linux_host_interpreter_scoped": linux.get("static_parser") is True and
          linux.get("subset_interpreter_host_tested") is True and
          linux.get("virtual_syscall_mock") is True and
          linux.get("virtual_namespace_mock") is True and
          linux.get("native_kernel_execution_verified") is False and
          linux.get("normal_app_support") is False and
          linux.get("real_runtime_mount") is False,
      "windows_metadata_only":win.get("metadata_parser") is True and
          win.get("nt_win32_runtime") is False and
          win.get("dll_loader") is False and
          win.get("application_execution_verified") is False,
      "macos_metadata_only":mac.get("metadata_parser") is True and
          mac.get("darwin_mach_runtime") is False and
          mac.get("dyld_or_frameworks") is False and
          mac.get("application_execution_verified") is False and
          mac.get("apple_silicon_supported") is False,
      "phase5_not_ready_to_merge":spec.get("phase5_full_completion") is False
          and spec.get("phase5_main_merge_authorized") is False
          and spec.get("public_release_allowed") is False,
      "no_kernel_code_claim":spec.get("native_kernel_code_modified") is False,
      "9front_auto_sync_stays_off":not (root/".github/workflows/sync-9front.yml").exists()
    }
    hashes={p:hashlib.sha256((root/p).read_bytes()).hexdigest()
        for paths in FILES.values() for p in paths if (root/p).is_file()}
    return {
      "schema":"ryzova-phase5-cross-platform-review/v1",
      "checks":checks,
      "stage_files":present,
      "static_foundation_validated":all(checks.values()),
      "kernel_linux_application_executed":False,
      "windows_application_executed":False,
      "macos_application_executed":False,
      "public_release_permitted":False,
      "merge_to_main_permitted":False,
      "runtime_qemu_execution_evidence":"NOT AVAILABLE: separate kernel integration test needed",
      "sha256":hashes,
      "remaining_gates":["native Linux ELF process loader and Ryzova syscall trap integration",
                         "actual Linux app execution under Ryzova native QEMU",
                         "real per-process Linux namespace mount and isolation review",
                         "supported loader/runtime semantics for Windows and macOS or explicit exclusions",
                         "full Phase 5 security acceptance and user authorization to merge"]
    }
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--out",default="artifacts/phase5/cross-platform-status.json")
    args=parser.parse_args()
    result=review()
    out=ROOT/args.out
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"checks":result["checks"],"merge_to_main_permitted":False},indent=2))
    return 0 if result["static_foundation_validated"] else 1
if __name__=="__main__":
    raise SystemExit(main())
