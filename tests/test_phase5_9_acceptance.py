# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 5.9 source-only evidence and negative claim tests."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from phase5_9_acceptance import inspect

class Phase59AcceptanceTests(unittest.TestCase):
    def load(self):
        return json.loads((ROOT/"ryzova/compat/phase5-9-acceptance.json").read_text())
    def test_experimental_source_only_is_acceptable(self):
        r=inspect()
        self.assertTrue(r["experimental_source_foundation_acceptance"],r)
        self.assertTrue(r["phase6_research_ready"])
        self.assertFalse(r["product_compatibility_verified"])
        self.assertFalse(r["public_release_approved"])
    def test_cannot_forge_native_ryzova_execution(self):
        m=self.load()
        m["linux_native_ryzova_app_execution_verified"]=True
        self.assertFalse(inspect(manifest=m)["experimental_source_foundation_acceptance"])
    def test_cannot_forge_windows_or_macos_execution(self):
        for key in ("windows_application_execution_verified",
                    "macos_application_execution_verified"):
            m=self.load()
            m[key]=True
            with self.subTest(key=key):
                self.assertFalse(inspect(manifest=m)["experimental_source_foundation_acceptance"])
    def test_reject_production_or_public_release_claim(self):
        for key in ("production_compatibility_complete",
                    "public_binary_release_authorized"):
            m=self.load()
            m[key]=True
            with self.subTest(key=key):
                self.assertFalse(inspect(manifest=m)["experimental_source_foundation_acceptance"])
    def test_reject_unauthorized_merge_flag(self):
        m=self.load()
        m["source_merge_requested_by_user"]=False
        self.assertFalse(inspect(manifest=m)["experimental_source_foundation_acceptance"])
    def test_cannot_forge_qemu_evidence_through_static_manifest(self):
        r=inspect()
        self.assertTrue(r["merge_into_main_requires_external_git_ci_verification"])
        self.assertFalse(r["linux_app_executed_in_native_ryzova_kernel"])
    def test_forged_release_eligible_blocks_source_gate(self):
        release={"candidate_eligible":True,"publication_permitted_by_ci":False}
        self.assertFalse(inspect(release=release)["experimental_source_foundation_acceptance"])
if __name__=="__main__":unittest.main()
