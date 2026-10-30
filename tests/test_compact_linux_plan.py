# SPDX-License-Identifier: AGPL-3.0-only
"""Prevent regression baseline results from being promoted to V1 completion."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from compact_linux_baseline import validate,assess
class CompletionPlanTests(unittest.TestCase):
 def setUp(self):self.plan=json.loads((ROOT/'ryzova/compact/linux-v1-plan.json').read_text())
 def suites(self):return {name:{'run':count,'successful':True,'failures':[],'errors':[],'skipped':[]} for name,count in self.plan['baseline']['minimum_tests'].items()}
 def test_frozen_plan_is_valid_and_has_explicit_exclusions(self):
  self.assertEqual(validate(self.plan),[]);self.assertEqual(len(self.plan['phases']),8);self.assertIn('Operational ARM64 and physical hardware qualification',self.plan['excluded_from_v1']);p=copy.deepcopy(self.plan);p['baseline']['minimum_tests']['phase9']=1;self.assertTrue(validate(p))
 def test_green_baseline_does_not_complete_application_acceptance(self):
  report=assess(self.plan,self.suites(),[]);self.assertTrue(report['regression_qualified']);self.assertFalse(report['v1_complete']);self.assertFalse(report['merge_performed']);self.assertEqual(len(report['pending_acceptance']),17)
 def test_incomplete_discovery_cannot_pass(self):
  suites=self.suites();suites['phase9']['run']-=1;self.assertFalse(assess(self.plan,suites,[])['regression_qualified'])
 def test_skipped_tests_are_not_full_qualification(self):
  suites=self.suites();suites['phase9']['skipped']=[{'test':'required','reason':'missing fixtures'}];self.assertFalse(assess(self.plan,suites,[])['regression_qualified'])
 def test_failed_suite_cannot_pass(self):
  suites=self.suites();suites['phase5']['errors']=['broken'];self.assertFalse(assess(self.plan,suites,[])['regression_qualified'])
 def test_bad_fixture_or_diagnostic_mode_cannot_pass(self):
  self.assertFalse(assess(self.plan,self.suites(),['digest mismatch'])['regression_qualified']);self.assertFalse(assess(self.plan,self.suites(),[],True)['regression_qualified'])
 def test_missing_target_version_and_duplicate_target_are_rejected(self):
  p=copy.deepcopy(self.plan);p['targets'][1]['version']='';self.assertTrue(validate(p));p=copy.deepcopy(self.plan);p['targets'].append(p['targets'][0]);self.assertTrue(validate(p))
 def test_invalid_dependencies_and_unsupported_claims_are_rejected(self):
  p=copy.deepcopy(self.plan);p['phases'][1]['depends_on']=['CLX-08'];self.assertTrue(validate(p));p=copy.deepcopy(self.plan);p['automatic_merge']=True;self.assertTrue(validate(p))
 def test_requirement_cannot_be_marked_passed_without_evidence(self):
  p=copy.deepcopy(self.plan);p['requirements'][0]['state']='passed';self.assertTrue(validate(p))
 def test_strict_cli_fails_before_running_without_pinned_fixtures(self):
  import os
  env={k:v for k,v in os.environ.items() if k not in ('COMPACT_MUSL_DIR','COMPACT_SHELL_DIR','COMPACT_BUSYBOX_DIR')}
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'report.json';r=subprocess.run([sys.executable,str(ROOT/'scripts/compact_linux_baseline.py'),'--output',str(path)],env=env,capture_output=True,timeout=10)
   self.assertEqual(r.returncode,1,r.stderr);report=json.loads(path.read_text());self.assertFalse(report['regression_qualified']);self.assertEqual(report['suites'],{});self.assertFalse(report['v1_complete'])
if __name__=='__main__':unittest.main()
