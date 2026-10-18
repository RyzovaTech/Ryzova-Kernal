# SPDX-License-Identifier: AGPL-3.0-only
import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from phase6_closeout import inspect

class Phase6Closeout(unittest.TestCase):
    def manifest(self):
        return json.loads((ROOT/"ryzova/remote/phase6-closeout.json").read_text())
    def test_source_evidence_passes_but_kernel_resource_is_unverified(self):
        x=inspect()
        self.assertTrue(x["experimental_source_acceptable"],x)
        self.assertFalse(x["native_ryzova_remote_resources_working"])
        self.assertFalse(x["public_binary_release_permitted"])
    def test_cannot_claim_remote_ram_cpu_or_mount(self):
        for field in ("remote_kernel_ram_verified","additional_cpu_cores_verified",
                      "native_ryzova_9p_mount_verified","remote_machine_access_verified"):
            with self.subTest(field=field):
                document=self.manifest()
                document[field]=True
                self.assertFalse(inspect(manifest=document)["experimental_source_acceptable"])
    def test_public_release_override_rejected(self):
        doc=self.manifest()
        doc["public_release_authorized"]=True
        self.assertFalse(inspect(manifest=doc)["experimental_source_acceptable"])
    def test_no_implicit_source_merge_without_approval(self):
        doc=self.manifest()
        doc["source_merge_requested_by_user"]=False
        self.assertFalse(inspect(manifest=doc)["experimental_source_acceptable"])
    def test_release_evidence_must_remain_blocked(self):
        self.assertFalse(inspect(release={"candidate_eligible":True,
                            "publication_permitted_by_ci":False})["experimental_source_acceptable"])
if __name__=="__main__":unittest.main()
