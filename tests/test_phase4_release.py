# SPDX-License-Identifier: AGPL-3.0-only
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from phase4_release_gate import assess
from phase4_variant_gate import validate
from phase4_provenance import collect

ROOT=Path(__file__).resolve().parents[1]
class ReleaseContractTests(unittest.TestCase):
    def test_current_release_cannot_pass(self):
        result=assess()
        self.assertFalse(result["candidate_eligible"])
        self.assertFalse(result["publication_permitted_by_ci"])
        self.assertIn("scoped_redistribution_rights",result["missing"])
        self.assertIn("physical_qualification",result["missing"])
    def test_forged_physical_evidence_does_not_validate(self):
        from unittest.mock import patch
        import phase4_release_gate as gate
        original=gate.document
        def altered(root,path):
            d=original(root,path)
            if path=="ryzova/drivers/physical-tests.json":
                return {**d,"test_records":[{"driver":"fabricated"}],
                        "license_clearance":True,"maintainer_approval":"unknown",
                        "independent_lab_review":"unverified"}
            return d
        with patch.object(gate,"document",side_effect=altered):
            self.assertFalse(gate.assess()["checks"]["physical_qualification"])
    def test_current_builder_provenance_is_not_binary_reproducibility(self):
        r=collect()
        self.assertEqual(len(r["source_commit"]),40)
        self.assertEqual(set(r["source_trees"]),{"sys/src/9","sys/include","amd64/include"})
        self.assertFalse(r["binary_reproducible_across_build_hosts"])
    def test_experimental_variant_schema_passes_but_is_unqualified(self):
        import json
        p=json.loads((ROOT/"ryzova/sdk/examples/amd64-minimal-variant.json").read_text())
        c=json.loads((ROOT/"ryzova/sdk/kernel-contract.json").read_text())
        r=validate(p,c)
        self.assertTrue(r["schema_compatible"],r)
        self.assertFalse(r["boot_qualified"])
        self.assertFalse(r["redistribution_approved"])
    def test_rejects_variant_abi_mismatch(self):
        import json
        p=json.loads((ROOT/"ryzova/sdk/examples/amd64-minimal-variant.json").read_text())
        c=json.loads((ROOT/"ryzova/sdk/kernel-contract.json").read_text())
        p["kernel_abi"]="stable-1"
        self.assertFalse(validate(p,c)["schema_compatible"])
    def test_rejects_unverified_binary_compatibility_claim(self):
        import json
        p=json.loads((ROOT/"ryzova/sdk/examples/amd64-minimal-variant.json").read_text())
        c=json.loads((ROOT/"ryzova/sdk/kernel-contract.json").read_text())
        p["windows_binary_compatibility"]=True
        self.assertFalse(validate(p,c)["schema_compatible"])
if __name__=="__main__":
    unittest.main()
