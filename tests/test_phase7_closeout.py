# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from phase6_native_9p import payload_for_commit
from phase7_secure_closeout import gateway_metrics_report,closeout

SHA="a"*40
METRICS={"gateway_9p_frames":9,"peer_9p_frames":9,
         "tls_client_pinned_sessions":1,"tls_server_pinned_sessions":1,
         "denied_guest_writes":0}
NATIVE={"passed":True,"source_commit":SHA,
    "payload_sha256":hashlib.sha256(payload_for_commit(SHA)).hexdigest()}
class CloseoutTests(unittest.TestCase):
    def test_good_gateway_is_research_only(self):
        p=gateway_metrics_report(SHA,METRICS,NATIVE)
        self.assertTrue(p["passed"])
        self.assertFalse(p["native_ryzova_kernel_tls_client_verified"])
        self.assertFalse(p["public_release_permitted"])
    def test_wrong_source_is_rejected(self):
        self.assertFalse(gateway_metrics_report("b"*40,METRICS,NATIVE)["passed"])
    def test_missing_peer_tls_is_rejected(self):
        m=dict(METRICS,tls_server_pinned_sessions=0)
        self.assertFalse(gateway_metrics_report(SHA,m,NATIVE)["passed"])
    def test_missing_real_9p_frames_is_rejected(self):
        m=dict(METRICS,peer_9p_frames=0)
        self.assertFalse(gateway_metrics_report(SHA,m,NATIVE)["passed"])
    def test_denied_guest_write_is_not_considered_clean(self):
        m=dict(METRICS,denied_guest_writes=1)
        self.assertFalse(gateway_metrics_report(SHA,m,NATIVE)["passed"])
    def test_unavailable_live_qemu_is_not_ready(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(closeout(Path(d),SHA)["ready"])
    def test_full_research_scope_requires_native_proof(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)/"artifacts"/"phase3"
            base.mkdir(parents=True)
            (base/"phase7-secure-bridge.json").write_text(json.dumps(gateway_metrics_report(SHA,METRICS,NATIVE)))
            (base/"phase6-native-9p.json").write_text(json.dumps(NATIVE))
            (base/"phase7-entry.json").write_text(json.dumps({"ready":True,"source_commit":SHA,
                "public_release_permitted":False}))
            (base/"result.txt").write_text("Source SHA: "+SHA+"\n"
                "V6 source-built QEMU guest network 9P mount and SHA: True\n"
                "V7 native guest 9P via pinned mutual TLS host gateway: True\n")
            self.assertTrue(closeout(Path(d),SHA)["ready"])
            (base/"phase7-entry.json").write_text(json.dumps({"ready":False,"source_commit":SHA}))
            self.assertFalse(closeout(Path(d),SHA)["ready"])
if __name__=="__main__":unittest.main()
