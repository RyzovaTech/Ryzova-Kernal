# SPDX-License-Identifier: AGPL-3.0-only
"""Repeat the existing compatibility baseline; never declares V1 complete or merges."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
PLAN=ROOT/'ryzova/compact/linux-v1-plan.json'

def validate(plan):
 errors=[]
 if plan.get('schema')!='compact-linux-v1-plan/v1':errors.append('invalid schema')
 baseline=plan.get('baseline',{})
 if not re.fullmatch('[a-f0-9]{40}',baseline.get('reference_head','')) or baseline.get('minimum_tests')!={'phase5':63,'phase9':109} or not baseline.get('core_sha256') or any(not re.fullmatch('[a-f0-9]{64}',v) for v in baseline.get('core_sha256',{}).values()):errors.append('invalid frozen baseline reference or test floors')
 if plan.get('automatic_merge') is not False or plan.get('general_linux_compatibility_claim') is not False:errors.append('unsupported merge/compatibility claim')
 phases=plan.get('phases',[]);ids=[p.get('id') for p in phases]
 if ids!=[f'CLX-{i:02}' for i in range(1,9)]:errors.append('expected eight ordered phases')
 seen=set()
 for phase in phases:
  if any(d not in seen for d in phase.get('depends_on',[])):errors.append('invalid dependency order')
  seen.add(phase.get('id'))
 targets=plan.get('targets',[]);tids=[t.get('id') for t in targets]
 if len(tids)!=len(set(tids)) or not {'busybox','python','git','gcc','binutils','make','musl'}<=set(tids):errors.append('missing/duplicate target')
 for target in targets:
  if not target.get('version') or not target.get('upstream_source','').startswith('https://') or not target.get('workflows'):errors.append('unpinned target/workflow')
 reqs=plan.get('requirements',[]);rids=[r.get('id') for r in reqs]
 if len(rids)!=len(set(rids)) or len(reqs)<17:errors.append('missing/duplicate acceptance requirement')
 for req in reqs:
  if req.get('phase') not in ids or any(t not in tids for t in req.get('targets',[])) or not req.get('acceptance'):errors.append('invalid requirement mapping')
  if req.get('state') not in ('pending','partial','passed'):errors.append('invalid requirement state')
  if req.get('state')=='passed' and not req.get('evidence'):errors.append('passed requirement without evidence')
 return errors

def suite(name,output):
 sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'scripts')]
 loaded=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern=f'test_{name}*.py')
 result=unittest.TextTestRunner(verbosity=2).run(loaded)
 data={'run':result.testsRun,'failures':[str(t) for t,_ in result.failures],'errors':[str(t) for t,_ in result.errors],'skipped':[{'test':str(t),'reason':why} for t,why in result.skipped],'successful':result.wasSuccessful()}
 output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(data,indent=2)+'\n')
 return 0 if result.wasSuccessful() else 1

def fixtures():
 checks=[];errors=[]
 musl=Path(os.environ.get('COMPACT_MUSL_DIR','/nonexistent')).resolve();shell=Path(os.environ.get('COMPACT_SHELL_DIR','/nonexistent')).resolve();busybox=Path(os.environ.get('COMPACT_BUSYBOX_DIR','/nonexistent')).resolve()
 sys.path.insert(0,str(ROOT/'scripts'))
 from phase9_dynamic import SOURCE_SHA256
 from phase9_compiler import SHA256
 from phase9_busybox import FIXTURES
 from phase9_shell import DIGEST
 pinned=[(musl/'musl-1.2.6.tar.gz',SOURCE_SHA256),(musl/'tcc-0.9.27.tar.bz2',SHA256),(shell/'busybox',DIGEST)]
 pinned += [(busybox/('busybox-'+name),entry[1]) for name,entry in FIXTURES.items()]
 for path,expected in pinned:
  actual=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
  checks.append({'path':str(path),'sha256':actual,'expected_sha256':expected,'matched':actual==expected})
  if actual!=expected:errors.append('missing or mismatched fixture: '+str(path))
 for name in ('musl-libc.so','tcc-fixture'):
  path=musl/name
  if not path.is_file():errors.append('missing built fixture: '+str(path))
  else:checks.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'build_output':True})
 return checks,errors

def assess(plan,suites,fixture_errors,diagnostic=False):
 errors=list(validate(plan))+list(fixture_errors)
 for name,minimum in plan.get('baseline',{}).get('minimum_tests',{}).items():
  report=suites.get(name,{})
  if report.get('run',0)<minimum:errors.append(name+': incomplete discovery')
  if not report.get('successful') or report.get('failures') or report.get('errors'):errors.append(name+': failing suite')
  if report.get('skipped'):errors.append(name+': skipped tests are not qualification evidence')
 return {'regression_qualified':not errors and not diagnostic,'diagnostic':diagnostic,'blockers':errors,'v1_complete':False,'merge_performed':False,'pending_acceptance':[r['id'] for r in plan['requirements'] if r['state']!='passed']}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'artifacts/compact-linux-v1/baseline.json');parser.add_argument('--check-plan',action='store_true');parser.add_argument('--diagnostic',action='store_true');parser.add_argument('--suite',choices=('phase5','phase9'));args=parser.parse_args()
 if args.suite:return suite(args.suite,args.output)
 plan=json.loads(PLAN.read_text());errors=validate(plan)
 if args.check_plan:
  print(json.dumps({'plan_valid':not errors,'errors':errors,'v1_complete':False,'pending_requirements':len(plan['requirements'])},indent=2));return bool(errors)
 output=args.output.resolve();output.parent.mkdir(parents=True,exist_ok=True);checks,fixture_errors=fixtures()
 overrides={k:os.environ.get(k) for k in ('COMPACT_DISABLE_LSAN','COMPACT_DISABLE_NATIVE_UNIX_BIND','ASAN_OPTIONS','LSAN_OPTIONS','UBSAN_OPTIONS') if os.environ.get(k)}
 if overrides:fixture_errors.append('qualification environment has disabled checks: '+','.join(overrides))
 suites={}
 if not errors and (not fixture_errors or args.diagnostic):
  for name in ('phase5','phase9'):
   path=output.parent/(name+'-suite.json')
   child=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--suite',name,'--output',str(path)],cwd=ROOT)
   suites[name]=json.loads(path.read_text()) if path.is_file() else {'successful':False,'run':0,'errors':['suite report missing']}
   if child.returncode:suites[name]['successful']=False
 status=assess(plan,suites,fixture_errors,args.diagnostic)
 try:head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True,stderr=subprocess.DEVNULL).strip()
 except (subprocess.CalledProcessError,FileNotFoundError):head=None
 core={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() if (ROOT/p).is_file() else None for p in plan['baseline']['core_sha256']}
 report={'schema':'compact-linux-baseline/v1','reference_head':plan['baseline']['reference_head'],'source_checkout':head,'core_sha256':core,'core_matches_reference':core==plan['baseline']['core_sha256'],'python':platform.python_version(),'cc':subprocess.check_output(['cc','--version'],text=True).splitlines()[0],'fixtures':checks,'suites':suites,'qualification_overrides':overrides,**status}
 output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('regression_qualified','diagnostic','v1_complete','blockers','pending_acceptance')},indent=2))
 # Diagnostics may succeed as a command, but never become qualification evidence.
 return 0 if status['regression_qualified'] or (args.diagnostic and all(s.get('successful') for s in suites.values()) and len(suites)==2) else 1
if __name__=='__main__':raise SystemExit(main())
