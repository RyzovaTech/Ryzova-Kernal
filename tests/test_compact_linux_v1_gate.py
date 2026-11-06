# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from compact_linux_v1_gate import IDS,PHASES,TARGETS,assess


class FinalGateTests(unittest.TestCase):
    def complete(self,root):
        directory=root/'docs/validation'
        directory.mkdir(parents=True,exist_ok=True)
        (directory/'stage.json').write_text(json.dumps({
            'acceptance':{x:'passed' for x in IDS}}))
        (directory/'compact-linux-v1-final-acceptance.json').write_text(
            json.dumps({'phase':'CLX-08','v1_complete':True,
                        'native':{'source_built_qemu':True},
                        'acceptance':{x:'passed' for x in IDS}}))
        return {'schema':'compact-linux-v1-plan/v1',
                'requirements':[{'id':x,'state':'passed',
                                'evidence':'docs/validation/stage.json'}
                                for x in IDS],
                'phases':[{'id':x,'state':'complete'} for x in PHASES],
                'targets':[{'id':x,'release_binary_sha256':'a'*64}
                           for x in TARGETS]}

    def test_complete_metadata_schema_still_needs_separate_review(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            r=assess(root,self.complete(root))
            self.assertTrue(r['ready_for_separately_authorized_merge'])
            self.assertIn('reviewer approval',r['warning'])

    def test_partial_and_missing_binary_locks_block(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=self.complete(root)
            p['requirements'][3]['state']='partial'
            p['phases'][3]['state']='in_progress'
            p['targets'][0]['release_binary_sha256']=None
            r=assess(root,p)
            self.assertFalse(r['ready_for_separately_authorized_merge'])
            self.assertIn('MEM-PROC',r['unpassed_requirements'])
            self.assertIn('CLX-04',r['unfinished_phases'])
            self.assertTrue(r['missing_target_binary_locks'])

    def test_forged_pass_and_path_escape_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=self.complete(root)
            p['requirements'][0]['evidence']='../../etc/passwd'
            self.assertIn('FS-ROOT',assess(root,p)['missing_verified_evidence'])
            p['requirements'][0]['evidence']='docs/validation/stage.json'
            (root/'docs/validation/stage.json').write_text('{}')
            self.assertIn('FS-ROOT',assess(root,p)['missing_verified_evidence'])

    def test_missing_final_native_evidence_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=self.complete(root)
            (root/'docs/validation/compact-linux-v1-final-acceptance.json').unlink()
            self.assertFalse(assess(root,p)['final_native_evidence_present'])

    def test_unreviewed_scope_changes_and_duplicates_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=self.complete(root)
            p['requirements'][0]['id']='MISSING'
            with self.assertRaises(ValueError):assess(root,p)
            p=self.complete(root)
            p['targets'][0]['id']='replacement'
            with self.assertRaises(ValueError):assess(root,p)

    def test_current_source_plan_cannot_be_declared_complete(self):
        plan=json.loads((ROOT/'ryzova/compact/linux-v1-plan.json').read_text())
        r=assess(ROOT,plan)
        self.assertFalse(r['ready_for_separately_authorized_merge'])
        self.assertIn('APP-PYTHON',r['unpassed_requirements'])
        self.assertIn('TLS-GUEST',r['unpassed_requirements'])


if __name__=='__main__':
    unittest.main()
