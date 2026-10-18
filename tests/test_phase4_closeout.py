# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import phase4_closeout as close

class CloseoutTests(unittest.TestCase):
    def test_current_worktree_reports_phase5_experimental_only(self):
        report=close.evaluate(run_baseline=False)
        self.assertTrue(report["engineering_infrastructure_passed"],report)
        self.assertTrue(report["phase5_experimental_planning_allowed"])
        self.assertFalse(report["phase5_compatibility_implemented"])
        self.assertFalse(report["phase4_production_qualification"])
        self.assertFalse(report["public_release_permitted"])
    def test_reintroduced_9front_sync_rejects_closeout(self):
        result=close.integration()
        altered={**result, "checks":{**result["checks"],"upstream_auto_sync_absent":False},
                 "pass":False}
        with patch.object(close,"integration",return_value=altered):
            report=close.evaluate(run_baseline=False)
            self.assertFalse(report["engineering_infrastructure_passed"])
    def test_release_gate_becoming_eligible_is_not_automatic_permission(self):
        r=close.release_assessment()
        r["candidate_eligible"]=True
        with patch.object(close,"release_assessment",return_value=r):
            self.assertFalse(close.evaluate(run_baseline=False)["checks"]["public_release_is_blocked"])
if __name__=="__main__":unittest.main()
