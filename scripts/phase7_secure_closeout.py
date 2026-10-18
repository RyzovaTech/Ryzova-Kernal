#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 7.5/7.6: live QEMU mTLS-proxied 9P proof, not native guest TLS."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

from phase6_native_9p import payload_for_commit

ROOT = Path(__file__).resolve().parents[1]


def gateway_metrics_report(commit, metrics, native_evidence):
    if not re.fullmatch(r"[0-9a-f]{40}",commit):
        raise ValueError("source commit required")
    checks={
        "native_qemu_guest_file_read_verified":
            native_evidence.get("passed") is True
            and native_evidence.get("source_commit") == commit
            and native_evidence.get("payload_sha256") ==
                hashlib.sha256(payload_for_commit(commit)).hexdigest(),
        "gateway_mutual_tls_client_verified":
            type(metrics.get("tls_client_pinned_sessions")) is int
            and metrics.get("tls_client_pinned_sessions") >= 1,
        "peer_mutual_tls_server_verified":
            type(metrics.get("tls_server_pinned_sessions")) is int
            and metrics.get("tls_server_pinned_sessions") >= 1,
        "actually_forwarded_native_9p_frames":
            type(metrics.get("gateway_9p_frames")) is int
            and metrics.get("gateway_9p_frames") >= 5,
        "actually_received_tls_9p_frames":
            type(metrics.get("peer_9p_frames")) is int
            and metrics.get("peer_9p_frames") >= 5
            and metrics.get("peer_9p_frames") == metrics.get("gateway_9p_frames"),
        "no_guest_write_requests":metrics.get("denied_guest_writes") == 0,
    }
    return {
        "schema":"ryzova-phase7-secure-bridge/v1",
        "source_commit":commit,"passed":all(checks.values()),"checks":checks,
        "metrics":metrics,
        "gateway_tls_protocol":"TLS1.3 mutual leaf certificate pins",
        "guest_to_gateway_transport":"plaintext and unauthenticated (CI ONLY)",
        "gateway_to_peer_transport":"TLS1.3 mutually authenticated (host localhost)",
        "native_ryzova_kernel_tls_client_verified":False,
        "external_machine_verified":False,
        "remote_physical_ram_verified":False,
        "additional_native_cpu_cores_verified":False,
        "public_release_permitted":False,
    }


def closeout(root, commit):
    try:
        out=root/"artifacts"/"phase3"
        evidence=json.loads((out/"phase7-secure-bridge.json").read_text())
        native=json.loads((out/"phase6-native-9p.json").read_text())
        entry=json.loads((out/"phase7-entry.json").read_text())
        result=(out/"result.txt").read_text()
    except (OSError, ValueError, UnicodeError):
        return {"schema":"ryzova-phase7-full-closeout/v1",
                "ready":False,"checks":{"live_qemu_evidence_available":False}}
    if not all(isinstance(obj,dict) for obj in (evidence,native,entry)):
        return {"schema":"ryzova-phase7-full-closeout/v1",
                "ready":False,"checks":{"live_qemu_evidence_valid":False}}
    proof=gateway_metrics_report(commit,evidence.get("metrics",{}),native)
    checks={
      "native_source_built_kernel_verified":entry.get("ready") is True
        and entry.get("source_commit") == commit,
      "verified_tls_peer_metrics_and_native_9p":proof["passed"] is True
        and evidence.get("passed") is True and evidence.get("source_commit") == commit
        and evidence.get("checks") == proof["checks"],
      "recorded_transport_scope_explicit":evidence.get("native_ryzova_kernel_tls_client_verified") is False
        and evidence.get("external_machine_verified") is False,
      "exact_commit_sha_in_runner":("Source SHA: " + commit + "\n") in result,
      "native_9p_guest_sha_and_pinned_tls_positive":
        "V6 source-built QEMU guest network 9P mount and SHA: True\n" in result
        and "V7 native guest 9P via pinned mutual TLS host gateway: True\n" in result,
      "public_release_stays_blocked":evidence.get("public_release_permitted") is False
        and entry.get("public_release_permitted") is False,
      "remote_ram_cpu_stays_unclaimed":
        evidence.get("remote_physical_ram_verified") is False
        and evidence.get("additional_native_cpu_cores_verified") is False,
    }
    return {"schema":"ryzova-phase7-full-closeout/v1",
            "source_commit":commit,
            "ready":all(checks.values()),"checks":checks,
            "scope":"source-built Ryzova QEMU -> plaintext local 9P gateway -> mTLS1.3 isolated host peer",
            "native_guest_has_tls_stack":False,
            "remote_physical_machine_tested":False,
            "phase7_research_source_complete":all(checks.values()),
            "phase7_product_feature_complete":False,
            "release_allowed":False,
            "blockers":["native guest-to-peer end-to-end TLS and identity provisioning",
                        "separate network/physical VM, concurrency, revocation and outage qualification",
                        "native guest memory/CPU subsystem integration and physical hardware evidence"]}


def main():
    commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    report=closeout(ROOT,commit)
    out=ROOT/"artifacts"/"phase3"/"phase7-secure-closeout.json"
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    for name,value in report["checks"].items():
        print("PHASE7 FULL", "PASS" if value else "FAIL",name,flush=True)
    print("PHASE7 RESEARCH SOURCE READY",report["ready"],flush=True)
    return 0 if report["ready"] else 1


if __name__=="__main__":
    raise SystemExit(main())
