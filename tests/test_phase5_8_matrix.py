# SPDX-License-Identifier: AGPL-3.0-only
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from phase5_matrix import review

class CrossPlatformPolicyTests(unittest.TestCase):
    def test_current_scoped_foundations(self):
        result=review()
        self.assertTrue(result["static_foundation_validated"],result)
        self.assertFalse(result["kernel_linux_application_executed"])
        self.assertFalse(result["merge_to_main_permitted"])
    def test_forged_native_linux_execution_claim_fails(self):
        import json
        root=Path(__file__).resolve().parents[1]
        document=json.loads((root/"ryzova/compat/phase5-status.json").read_text())
        document["platforms"]["linux"]["native_kernel_execution_verified"]=True
        self.assertFalse(review(root,document)["static_foundation_validated"])
    def test_forged_windows_execution_claim_fails(self):
        import json
        root=Path(__file__).resolve().parents[1]
        document=json.loads((root/"ryzova/compat/phase5-status.json").read_text())
        document["platforms"]["windows"]["application_execution_verified"]=True
        self.assertFalse(review(root,document)["static_foundation_validated"])
    def test_forged_macos_execution_claim_fails(self):
        import json
        root=Path(__file__).resolve().parents[1]
        document=json.loads((root/"ryzova/compat/phase5-status.json").read_text())
        document["platforms"]["macos"]["application_execution_verified"]=True
        self.assertFalse(review(root,document)["static_foundation_validated"])
    def test_merge_authorization_cannot_be_assumed(self):
        import json
        root=Path(__file__).resolve().parents[1]
        document=json.loads((root/"ryzova/compat/phase5-status.json").read_text())
        document["phase5_main_merge_authorized"]=True
        self.assertFalse(review(root,document)["static_foundation_validated"])
if __name__=="__main__":unittest.main()
