# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed Compact Linux V1 completion metadata gate.

Metadata consistency is not a replacement for independently executed
native QEMU, security, target application and release authorization gates.
"""
import argparse
import json
from pathlib import Path
import re

IDS = (
    'FS-ROOT','FS-ISOLATION','FS-PERSIST','MEM-PROC','RESOURCE',
    'AMD64-ABI','NET-PEERS','TLS-GUEST','TTY-JOBS','APP-BUSYBOX',
    'APP-PYTHON','APP-GIT','APP-C-SDK','LOCKS','NATIVE-EVIDENCE',
    'INSTALL-RECOVERY','INTEGRATION',
)
PHASES = ('CLX-01','CLX-02','CLX-03','CLX-04','CLX-05','CLX-06','CLX-07','CLX-08')
TARGETS = frozenset(('busybox','python','git','gcc','binutils','make','musl'))
HEX = re.compile(r'[0-9a-f]{64}\Z')


def _validated_evidence(root, path, requirement):
    if (not isinstance(path,str) or not path.startswith('docs/validation/')
            or not path.endswith('.json') or '..' in Path(path).parts):
        return False
    fp=(root/path).resolve()
    if not fp.is_relative_to(root) or not fp.is_file() or fp.stat().st_size>2000000:
        return False
    try:
        evidence=json.loads(fp.read_text(encoding='utf-8'))
        return (isinstance(evidence,dict) and
                evidence.get('acceptance',{}).get(requirement)=='passed')
    except (OSError,UnicodeError,ValueError,AttributeError):
        return False


def assess(root,plan,*,final_path='docs/validation/compact-linux-v1-final-acceptance.json'):
    root=Path(root).resolve()
    if (not root.is_dir() or not isinstance(plan,dict) or
            plan.get('schema')!='compact-linux-v1-plan/v1'):
        raise ValueError('invalid V1 plan and source root')
    req=plan.get('requirements')
    if (not isinstance(req,list) or len(req)!=len(IDS) or
            any(not isinstance(r,dict) for r in req)):
        raise ValueError('unexpected number of V1 acceptance requirements')
    by_id={r.get('id'):r for r in req}
    if len(by_id)!=len(IDS) or set(by_id)!=set(IDS):
        raise ValueError('missing, duplicated or additional acceptance requirement')
    open_ids=[]
    incomplete_proof=[]
    for rid in IDS:
        record=by_id[rid]
        if record.get('state')!='passed':
            open_ids.append(rid)
        elif not _validated_evidence(root,record.get('evidence'),rid):
            incomplete_proof.append(rid)
    state={p.get('id'):p.get('state') for p in plan.get('phases',[])
           if isinstance(p,dict)}
    unfinished_phases=[phase for phase in PHASES[1:]
                       if state.get(phase)!='complete']
    binaries=plan.get('targets')
    if (not isinstance(binaries,list) or len(binaries)!=7 or
            set(v.get('id') for v in binaries if isinstance(v,dict))!=TARGETS):
        raise ValueError('V1 must retain exactly seven frozen target names')
    missing_binary_locks=sorted(v.get('id','<invalid>') for v in binaries
                                if not isinstance(v.get('release_binary_sha256'),str)
                                or not HEX.fullmatch(v['release_binary_sha256']))
    final_file=(root/final_path).resolve()
    final_valid=False
    if (final_path.startswith('docs/validation/') and
            final_file.is_relative_to(root) and final_file.is_file()
            and final_file.stat().st_size<=2000000):
        try:
            end=json.loads(final_file.read_text(encoding='utf-8'))
            final_valid=(end.get('v1_complete') is True and
                         all(end.get('acceptance',{}).get(rid)=='passed'
                             for rid in IDS) and
                         end.get('phase')=='CLX-08' and
                         end.get('native',{}).get('source_built_qemu') is True)
        except (OSError,UnicodeError,ValueError,AttributeError):
            pass
    ready=(not open_ids and not incomplete_proof and not unfinished_phases
           and not missing_binary_locks and final_valid)
    return {'schema':'compact-linux-v1-final-gate/v1',
            'ready_for_separately_authorized_merge':ready,
            'requirements_passed':len(IDS)-len(open_ids),
            'requirements_total':len(IDS),
            'unpassed_requirements':open_ids,
            'missing_verified_evidence':incomplete_proof,
            'unfinished_phases':unfinished_phases,
            'missing_target_binary_locks':missing_binary_locks,
            'final_native_evidence_present':final_valid,
            'warning':'Metadata consistency only; native execution, exact-head CI and reviewer approval remain independent gates'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('.'))
    parser.add_argument('--plan',type=Path,default=Path('ryzova/compact/linux-v1-plan.json'))
    parser.add_argument('--require-complete',action='store_true')
    args=parser.parse_args()
    plan=json.loads((args.root/args.plan).read_text(encoding='utf-8'))
    report=assess(args.root,plan)
    print(json.dumps(report,sort_keys=True,indent=2))
    if args.require_complete and not report['ready_for_separately_authorized_merge']:
        raise SystemExit('CLX V1 completion blocked: required independent evidence remains open')
