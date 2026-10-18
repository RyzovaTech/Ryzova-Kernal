# SPDX-License-Identifier: AGPL-3.0-only
import hashlib,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from phase7_native_guest_tls import commands,inspect
from phase6_native_9p import payload_for_commit
SHA="a"*40
THUMB="b"*64
def log():
    return (b"\r\nRYZOVA_NATIVE_TLS_READ_BEGIN\r\n"+payload_for_commit(SHA).replace(b"\n",b"\r\n")+
      b"RYZOVA_NATIVE_TLS_READ_END\r\n"+
      hashlib.sha256(payload_for_commit(SHA)).hexdigest().encode()+b"\t/n/ryzova7/probe\r\n"+
      b"RYZOVA_RUNTIME_STAGE_16\r\nRYZOVA_RUNTIME_STAGE_17\r\nRYZOVA_RUNTIME_STAGE_18\r\nRYZOVA_RUNTIME_STAGE_19\r\nRYZOVA_NATIVE_TLS_DONE\r\n")
class NativeTLSProofTests(unittest.TestCase):
    def test_guest_command_requires_pinned_certificate_and_tlsclient(self):
        x=commands(THUMB)
        self.assertEqual(len(x),4)
        self.assertTrue(all(len(command)<230 for _,command in x))
        self.assertIn("tlsclient -n localhost -t",x[1][1])
        self.assertIn("srv -enq",x[1][1])
        self.assertIn("sha1sum -2 256",x[3][1])
    def test_good_real_protocol_evidence(self):
        p=inspect(log(),SHA,THUMB,{"native_tls12_sessions":1,
          "native_tls_9p_frames":7,"upstream_tls13_sessions":1})
        self.assertTrue(p["passed"],p)
        self.assertFalse(p["guest_mutual_tls_client_certificate_verified"])
    def test_no_remote_frames_is_denied(self):
        self.assertFalse(inspect(log(),SHA,THUMB,{"native_tls12_sessions":1,
          "native_tls_9p_frames":0,"upstream_tls13_sessions":1})["passed"])
    def test_wrong_file_content_is_denied(self):
        self.assertFalse(inspect(log(),"c"*40,THUMB,{"native_tls12_sessions":1,
          "native_tls_9p_frames":7,"upstream_tls13_sessions":1})["passed"])
    def test_bad_certificate_thumbprint(self):
        with self.assertRaises(ValueError):commands("bad")
    def test_missing_sha_or_completion_is_denied(self):
        self.assertFalse(inspect(b"RYZOVA_NATIVE_TLS_DONE",SHA,THUMB,{"native_tls12_sessions":1,
          "native_tls_9p_frames":7,"upstream_tls13_sessions":1})["passed"])
if __name__=="__main__":unittest.main()
