# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed seven-target source and release-ELF lock evidence verifier.

Two separate CI build runs identified identical target binary hashes.
This is NOT production release certification, guest app workflow testing,
or standalone proof of GitHub job provenance. Exact-head CI checks actual
fresh target-profile hashes against the recorded immutable source/ELF locks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

IDS=frozenset(('busybox','python','git','gcc','binutils','make','musl'))
HEX=re.compile(r'[0-9a-f]{64}\Z')
COMMIT=re.compile(r'[0-9a-f]{40}\Z')
SCHEMA='compact-linux-v1-binary-locks/v1'


class LockDenied(ValueError):
    pass


def verify(root, *, profile=None):
    root=Path(root).resolve()
    source=(root/'ryzova/compact/linux-target-sources.json').read_bytes()
    plan=json.loads((root/'ryzova/compact/linux-v1-plan.json').read_text())
    evidence=json.loads((root/'docs/validation/compact-linux-v1-binary-locks.json').read_text())
    sha=hashlib.sha256(source).hexdigest()
    if (plan.get('schema')!='compact-linux-v1-plan/v1'
            or evidence.get('schema')!=SCHEMA
            or evidence.get('abi')!='x86_64-linux-musl'
            or evidence.get('source_lock_sha256')!=sha
            or evidence.get('acceptance',{}).get('LOCKS')!='passed'):
        raise LockDenied('binary/source provenance denied')
    targets=plan.get('targets')
    images=evidence.get('binaries')
    if (type(targets) is not list or len(targets)!=7 or
            type(images) is not dict or set(images)!=IDS):
        raise LockDenied('frozen target collection changed')
    seen=set()
    for target in targets:
        if type(target) is not dict:
            raise LockDenied('invalid target')
        ident=target.get('id')
        if ident not in IDS or ident in seen:
            raise LockDenied('unknown or duplicate target')
        seen.add(ident)
        desc=images[ident]
        if (type(desc) is not dict or desc.get('version')!=target.get('version')
                or type(desc.get('bytes')) is not int or desc['bytes']<=0
                or type(desc.get('sha256')) is not str
                or not HEX.fullmatch(desc['sha256'])
                or target.get('release_binary_sha256')!=desc['sha256']
                or target.get('source_lock_status')!='verified-two-GitHub-CI-source-builds'):
            raise LockDenied('target release ELF lock mismatch: '+ident)
    req=next((x for x in plan.get('requirements',[])
              if type(x) is dict and x.get('id')=='LOCKS'),None)
    if (not req or req.get('state')!='passed'
            or req.get('evidence')!='docs/validation/compact-linux-v1-binary-locks.json'):
        raise LockDenied('LOCKS acceptance metadata mismatch')
    runs=evidence.get('independent_ci_builds')
    if type(runs) is not list or len(runs)<2 or len(runs)>8:
        raise LockDenied('two distinct successful build runs required')
    run_ids=set()
    heads=set()
    for run in runs:
        if type(run) is not dict:
            raise LockDenied('invalid build record')
        rid=run.get('run_id')
        head=run.get('head_sha')
        recorded=run.get('binary_sha256')
        if (type(rid) is not int or rid<=0 or rid in run_ids
                or type(head) is not str or not COMMIT.fullmatch(head) or head in heads
                or run.get('conclusion')!='success'
                or run.get('source_lock_sha256')!=sha
                or type(recorded) is not dict or set(recorded)!=IDS
                or any(recorded[ident]!=images[ident]['sha256'] for ident in IDS)):
            raise LockDenied('independent run hash/provenance mismatch')
        run_ids.add(rid);heads.add(head)
    if profile is not None:
        if (type(profile) is not dict
                or profile.get('schema')!='compact-linux-target-profiles/v1'
                or profile.get('source_lock_sha256')!=sha
                or profile.get('abi')!='x86_64-linux-musl'):
            raise LockDenied('live CI source lock mismatch')
        records=profile.get('targets')
        if type(records) is not list or len(records)!=7:
            raise LockDenied('actual seven-target profiles required')
        seen=set()
        for record in records:
            if type(record) is not dict:
                raise LockDenied('malformed live target profile')
            ident=record.get('target')
            if ident not in IDS or ident in seen:
                raise LockDenied('unrecognized live target')
            seen.add(ident)
            elf=record.get('elf')
            if (record.get('version')!=images[ident]['version']
                    or type(elf) is not dict
                    or elf.get('sha256')!=images[ident]['sha256']
                    or elf.get('bytes')!=images[ident]['bytes']):
                raise LockDenied('live release ELF differs from frozen lock: '+ident)
    return {'schema':SCHEMA,'binary_locks_verified':True,
            'source_lock_sha256':sha,'targets':len(IDS),
            'recorded_independent_runs':len(run_ids),
            'guest_linux_v1_complete':False,
            'note':'SHA provenance alone does not qualify native app workflows'}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,default=Path('.'))
    parser.add_argument('--profiles',type=Path)
    args=parser.parse_args()
    profile=json.loads(args.profiles.read_text()) if args.profiles else None
    print(json.dumps(verify(args.root,profile=profile),sort_keys=True))
