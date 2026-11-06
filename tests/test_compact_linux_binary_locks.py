# SPDX-License-Identifier: AGPL-3.0-only
"""Negative/reproducibility tests for the seven source/binary locks."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from compact_linux_binary_locks import verify,LockDenied

class BinaryLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files={x:(ROOT/x).read_bytes() for x in (
            'ryzova/compact/linux-v1-plan.json',
            'ryzova/compact/linux-target-sources.json',
            'docs/validation/compact-linux-v1-binary-locks.json')}

    def test_actual_two_run_sha_locks_consistent(self):
        r=verify(ROOT)
        self.assertTrue(r['binary_locks_verified'])
        self.assertEqual(r['recorded_independent_runs'],2)
        self.assertFalse(r['guest_linux_v1_complete'])

    def altered(self,path,modify):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for filename,body in self.files.items():
                p=root/filename
                p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(body)
            target=root/path
            data=json.loads(target.read_text())
            modify(data)
            target.write_text(json.dumps(data,indent=2))
            with self.assertRaises(LockDenied):
                verify(root)

    def test_mutated_binary_digest_denied(self):
        self.altered('ryzova/compact/linux-v1-plan.json',
                     lambda p:p['targets'][0].update(release_binary_sha256='0'*64))

    def test_false_second_build_or_duplicate_run_denied(self):
        def mutate(v):
            v['independent_ci_builds'][1]['run_id']=v['independent_ci_builds'][0]['run_id']
        self.altered('docs/validation/compact-linux-v1-binary-locks.json',mutate)

    def test_wrong_release_version_denied(self):
        self.altered('docs/validation/compact-linux-v1-binary-locks.json',
                     lambda p:p['binaries']['python'].update(version='3.13.0'))

    def test_missing_runtime_source_lock_denied(self):
        self.altered('docs/validation/compact-linux-v1-binary-locks.json',
                     lambda p:p.update(source_lock_sha256='0'*64))

    def test_live_profile_enforces_exact_binary_digest_and_size(self):
        source=json.loads(self.files['docs/validation/compact-linux-v1-binary-locks.json'])
        profile={'schema':'compact-linux-target-profiles/v1',
                 'source_lock_sha256':source['source_lock_sha256'],
                 'abi':'x86_64-linux-musl',
                 'targets':[{'target':k,'version':v['version'],
                             'elf':{'sha256':v['sha256'],'bytes':v['bytes']}}
                            for k,v in source['binaries'].items()]}
        self.assertTrue(verify(ROOT,profile=profile)['binary_locks_verified'])
        profile['targets'][0]['elf']['sha256']='0'*64
        with self.assertRaises(LockDenied):
            verify(ROOT,profile=profile)
        profile['targets'][0]['elf']['sha256']=source['binaries']['busybox']['sha256']
        profile['targets'][0]['elf']['bytes']+=1
        with self.assertRaises(LockDenied):
            verify(ROOT,profile=profile)


if __name__=='__main__':
    unittest.main()
