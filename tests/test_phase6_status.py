# SPDX-License-Identifier: AGPL-3.0-only
import json
import unittest
from pathlib import Path
from scripts.phase6_status import check
class Phase6StatusTests(unittest.TestCase):
    def test_scope_is_experimental_and_unmerged(self):
        r=check()
        self.assertTrue(r["host_prototype_foundation_valid"],r)
        self.assertFalse(r["ready_for_main_merge"])
        self.assertFalse(r["remote_ram_verified"])
        self.assertFalse(r["remote_cpu_verified"])
    def test_no_forged_remote_resource_claim(self):
        # Schema checker is strict, and the committed status keeps all capabilities false.
        p=Path(__file__).resolve().parents[1]
        x=json.loads((p/"ryzova/remote/phase6-status.json").read_text())
        self.assertFalse(x["internet_network_supported"])
        self.assertFalse(x["remote_physical_ram_supported"])
        self.assertFalse(x["actual_remote_cpu_supported"])
if __name__=="__main__":unittest.main()
