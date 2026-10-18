# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from phase4_5_stress import STAGES, check_extended_serial

def log():
    return ("\r\n".join([
        "262144 /tmp/ryzova-9p/phase45.mem",
        "RYZOVA_PHASE45_WAIT_OK",
        "RYZOVA_PHASE45_MEM_BEGIN",
        "2147483648 memory",
        "4096 pagesize",
        "1000/10000 user",
        "2/100 swap",
        "RYZOVA_PHASE45_MEM_END",
        "RYZOVA_RUNTIME_STAGE_11",
        "RYZOVA_RUNTIME_STAGE_12",
        "RYZOVA_RUNTIME_STAGE_13",
        "RYZOVA_PHASE45_DONE",
    ]) + "\r\n").encode()

class BoundedTests(unittest.TestCase):
    def test_spec_is_finite(self):
        self.assertEqual(len(STAGES), 3)
        self.assertIn("count 64", STAGES[0][1])
    def test_positive_log(self):
        self.assertTrue(check_extended_serial(log())["passed"])
    def test_incomplete_allocation(self):
        self.assertFalse(check_extended_serial(log().replace(b"262144", b"262143"))["passed"])
    def test_echo_is_not_a_pass(self):
        fake=log().replace(b"\r\nRYZOVA_PHASE45_WAIT_OK\r\n", b"\r\n")
        fake+=b"term% echo RYZOVA_PHASE45_WAIT_OK\r\n"
        self.assertFalse(check_extended_serial(fake)["passed"])
    def test_panic_is_failure(self):
        self.assertFalse(check_extended_serial(log()+b"panic: test only\r\n")["passed"])
    def test_no_completion(self):
        self.assertFalse(check_extended_serial(log().replace(b"\r\nRYZOVA_PHASE45_DONE\r\n",b"\r\n"))["passed"])
if __name__=="__main__":
    unittest.main()
