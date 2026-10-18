# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from phase6_native_9p import payload_for_commit, guest_commands, inspect_native_9p_serial

SHA="a"*40
def log():
    value=payload_for_commit(SHA)
    digest=hashlib.sha256(value).hexdigest().encode()
    return (b"\r\nRYZOVA_PHASE6_READ_BEGIN\r\n"+value.replace(b"\n",b"\r\n")+
            b"RYZOVA_PHASE6_READ_END\r\n"+digest+b"\t/n/ryzova6/probe\r\n"
            b"RYZOVA_RUNTIME_STAGE_14\r\nRYZOVA_RUNTIME_STAGE_15\r\n"
            b"RYZOVA_PHASE6_NATIVE_DONE\r\n")
class NativeGuestEvidenceTests(unittest.TestCase):
    def test_two_bounded_guest_commands(self):
        self.assertEqual(len(guest_commands()),2)
        self.assertIn("mount -n",guest_commands()[0][1])
        self.assertIn("sha1sum -2 256",guest_commands()[1][1])
        self.assertLess(guest_commands()[1][1].index("RYZOVA_RUNTIME_STAGE_15"),
                        guest_commands()[1][1].index("RYZOVA_PHASE6_NATIVE_DONE"))
    def test_standalone_success(self):
        self.assertTrue(inspect_native_9p_serial(log(),SHA,6)["passed"])
    def test_wrong_commit_is_not_success(self):
        self.assertFalse(inspect_native_9p_serial(log(),"b"*40,6)["passed"])
    def test_no_actual_tcp_frames_is_failure(self):
        self.assertFalse(inspect_native_9p_serial(log(),SHA,0)["passed"])
    def test_no_hash_is_failure(self):
        x=log().replace(b"/n/ryzova6/probe",b"/n/untrusted/probe")
        self.assertFalse(inspect_native_9p_serial(x,SHA,6)["passed"])
    def test_echoed_command_does_not_count(self):
        fake=b"term% echo RYZOVA_PHASE6_NATIVE_DONE\r\n"
        self.assertFalse(inspect_native_9p_serial(fake,SHA,6)["passed"])
    def test_panic_fails_closed(self):
        self.assertFalse(inspect_native_9p_serial(log()+b"panic: memory fault\r\n",SHA,6)["passed"])
if __name__=="__main__":unittest.main()
