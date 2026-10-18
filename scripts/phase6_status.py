#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.0–6.3 truthful host proof status; no kernel integration claims."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REQUIRED=[
 "ryzova/remote/trust.py","ryzova/remote/p9.py",
 "ryzova/remote/cache.py","ryzova/remote/compute.py",
 "tests/test_phase6_0_trust.py","tests/test_phase6_1_p9.py",
 "tests/test_phase6_2_cache.py","tests/test_phase6_3_compute.py",
 ".github/workflows/phase6-remote.yml"
]
def check(root=ROOT):
    spec=json.loads((root/"ryzova/remote/phase6-status.json").read_text())
    checks={
        "required_source_present":all((root/p).is_file() for p in REQUIRED),
        "schema":spec.get("schema")=="ryzova-phase6-experimental/v1",
        "stages":spec.get("stages")==["6.0","6.1","6.2","6.3"],
        "off_by_default":spec.get("default_enabled") is False,
        "loopback_only":spec.get("transport")=="authenticated-in-process-loopback"
            and spec.get("internet_network_supported") is False
            and spec.get("tls_peer_auth_supported") is False
            and spec.get("confidentiality_verified") is False,
        "9p_wire_not_native_mount":spec.get("remote_9p_client_wire_supported") is True
            and spec.get("remote_9p_network_mounted") is False,
        "remote_cache_not_ram":spec.get("remote_cache_page_size")==4096
            and spec.get("remote_cache_max_pages")==64
            and spec.get("remote_physical_ram_supported") is False,
        "pure_task_not_cpu":spec.get("delegated_task_types")==["sum_squares","dot"]
            and spec.get("actual_remote_cpu_supported") is False,
        "kernel_unmodified":spec.get("native_kernel_code_modified") is False,
        "main_merge_blocked":spec.get("main_merge_authorized") is False
            and spec.get("phase6_full_completion") is False
            and spec.get("public_release_allowed") is False,
        "source_upstream_sync_off":not (root/".github/workflows/sync-9front.yml").exists()
    }
    return {"schema":"ryzova-phase6-0-3-evidence/v1",
        "checks":checks,"host_prototype_foundation_valid":all(checks.values()),
        "kernel_9p_remote_mount_verified":False,
        "remote_ram_verified":False,"remote_cpu_verified":False,
        "ready_for_main_merge":False,
        "files_sha256":{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in REQUIRED if (root/p).is_file()},
        "remaining":["Phase 6.4 failure/telemetry/security model","Phase 6.5 network and QEMU integration",
                     "mutual TLS authenticated real peers","native kernel opt-in integration",
                     "public release security, legal, hardware review"]}
def main():
    report=check()
    out=ROOT/"artifacts/phase6/phase6-0-3.json"
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report["checks"],indent=2))
    return 0 if report["host_prototype_foundation_valid"] else 1
if __name__=="__main__":
    raise SystemExit(main())
