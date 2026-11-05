# SPDX-License-Identifier: AGPL-3.0-only
"""Source-built Ryzova Kernel: initial-thread TLS execution and failure gates."""
import argparse
import functools
import http.server
import json
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import threading

from compact_windows_w2 import ROOT, PREFERRED
from compact_windows_w6_native import bootstrap_provenance, digest, extract_kernel, parse_cases, session, standalone
from compact_windows_w7_tls import tls_fixture, verify_reference
from compact_windows_w7_imports import verify_reference as verify_import_reference, EXPECTED_CALLS
from compact_windows_w7_startup import verify_reference as verify_startup_reference, EXPECTED_CALLS as STARTUP_CALLS, LOW_MASK, HIGH_MASK
from compact_windows_w7_sync import verify_reference as verify_sync_reference, sync_fixture, EXPECTED_CALLS as SYNC_CALLS, LOW_MASK as SYNC_LOW, HIGH_MASK as SYNC_HIGH


def images_and_cases(ref):
    receipt = verify_reference(ref)
    api_receipt = verify_import_reference(ref)
    startup_receipt = verify_startup_reference(ref)
    sync_receipt = verify_sync_reference(ref)
    bad = bytearray(tls_fixture())
    # The callback vector lives in the third, read-only section.
    raw = struct.unpack_from('<I', bad, 0x188+2*40+20)[0]
    struct.pack_into('<Q', bad, raw+112, PREFERRED+0x2000)
    images = {'tls': (ref/'tls.exe').read_bytes(), 'api-set': (ref/'api-set.exe').read_bytes(),
              'startup-api': (ref/'startup-api.exe').read_bytes(),
              'sync-api': (ref/'sync-api.exe').read_bytes(), 'sync-blocked': sync_fixture(blocking=True),
              'tls-loop': tls_fixture(callback_code=b'\xeb\xfe'),
              'tls-fault': tls_fixture(callback_code=b'\x0f\x0b'),
              'tls-denied': bytes(bad)}
    cases = {'tls': dict(image='tls', status=0, code=9, out='', err=''),
             'api-set': dict(image='api-set', status=0, code=37, out='', err=''),
             'startup-api': dict(image='startup-api', status=0, code=41, out='', err='', args=f'-a {LOW_MASK} -A {HIGH_MASK}'),
             'startup-policy-low': dict(image='startup-api', status=10, admission=True, args=f'-a 268435455 -A {HIGH_MASK}'),
             'startup-policy-high': dict(image='startup-api', status=10, admission=True, args=f'-a {LOW_MASK}'),
             'sync-api': dict(image='sync-api', status=0, code=43, out='', err='', args=f'-a {SYNC_LOW} -A {SYNC_HIGH}'),
             'sync-policy': dict(image='sync-api', status=10, admission=True, args=f'-a {SYNC_LOW}'),
             'sync-blocked': dict(image='sync-blocked', status=10, out='', err='', args=f'-a {SYNC_LOW} -A {SYNC_HIGH}'),
             'tls-loop': dict(image='tls-loop', status=8, steps=16, out='', err='', args='-b 16'),
             'tls-fault': dict(image='tls-fault', status=7, out='', err=''),
             'tls-denied': dict(image='tls-denied', status=4, admission=True)}
    return receipt, api_receipt, startup_receipt, sync_receipt, images, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--bootstrap-gzip', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    out = ROOT/'artifacts/compact-windows/w7-native';out.mkdir(parents=True, exist_ok=True)
    base_sha = bootstrap_provenance(args.image, args.bootstrap_gzip)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    receipt, api_receipt, startup_receipt, sync_receipt, images, cases = images_and_cases(args.reference)
    for name, data in images.items():
        (out/(name+'.exe')).write_bytes(data)
    archive = out/'source.tgz'
    files = subprocess.check_output(['git', 'ls-files', 'sys/src/9', 'sys/include', 'amd64/include',
                                     'ryzova/compat/windows'], cwd=ROOT, text=True).splitlines()
    with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
        for path in sorted(files):
            tar.add(ROOT/path, arcname=path.replace('ryzova/compat/windows', 'sys/src/cmd/compact-windows', 1), recursive=False)
    archive_sha = digest(archive)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(out))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 8000), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        commands = ["ip/ipconfig -d ether /net/ether0; webfs",
                    'hget http://10.0.2.2:8000/source.tgz > /tmp/cw-source.tgz; sha1sum -2 256 /tmp/cw-source.tgz',
                    'cd /; mkdir -p /sys/src/cmd/compact-windows; tar xzf /tmp/cw-source.tgz',
                    'cd /sys/src/cmd/compact-windows; mk install > /tmp/cw-build.log >[2=1] && echo CW_NATIVE_BUILD_OK; cat /tmp/cw-build.log',
                    'cd /sys/src/9/pc64; mk > /tmp/cw-kernel.log >[2=1] && echo CW_KERNEL_BUILD_OK; tail -n 30 /tmp/cw-kernel.log',
                    '9fs 9fat; cd /sys/src/9/pc64; cp 9pc64 /n/9fat/9pc64 && cmp 9pc64 /n/9fat/9pc64 && echo CW_KERNEL_COPY_OK; sha1sum -2 256 9pc64; sha1sum -2 256 /n/9fat/9pc64',
                    'sha1sum -2 256 /amd64/bin/compact-windows; echo sync >> /srv/hjfs.cmd; sleep 3']
        log = session(args.image, commands, out, 'build', 850,
                      {3: 'CW_NATIVE_BUILD_OK', 4: 'CW_KERNEL_BUILD_OK', 5: 'CW_KERNEL_COPY_OK'})
        if not re.search(rb'(?m)^'+archive_sha.encode()+rb'\s+/tmp/cw-source.tgz\r?$', log):
            raise ValueError('guest source archive mismatch')
        kernels = re.findall(rb'(?m)^([0-9a-f]{64})\s+(?:9pc64|/n/9fat/9pc64)\r?$', log)
        runtimes = re.findall(rb'(?m)^([0-9a-f]{64})\s+/amd64/bin/compact-windows\r?$', log)
        if len(kernels) != 2 or kernels[0] != kernels[1] or len(runtimes) != 1:
            raise ValueError('native kernel/runtime identity mismatch')
        extract_kernel(args.image, out, kernels[0].decode())
        commands = ["cat '#Z/version'; cat '#Z/foundation'; echo CW_IDENTITY_END",
                    'ip/ipconfig -d ether /net/ether0; webfs',
                    'sha1sum -2 256 /amd64/bin/compact-windows']
        for name in images:
            commands.append(f'hget http://10.0.2.2:8000/{name}.exe > /tmp/cw-{name}.exe; sha1sum -2 256 /tmp/cw-{name}.exe')
        for name, spec in cases.items():
            commands.append(f"echo CW_CASE_{name}_BEGIN; /amd64/bin/compact-windows {spec.get('args', '')} /tmp/cw-{spec['image']}.exe; echo CW_CASE_{name}_END")
        fresh = session(args.image, commands, out, 'fresh', 120)
        if b'Ryzova Kernel 0.1.0-dev' not in fresh or b'9front-derived' not in fresh or not standalone(fresh, 'CW_IDENTITY_END'):
            raise ValueError('fresh source-built guest identity')
        if not re.search(rb'(?m)^'+runtimes[0]+rb'\s+/amd64/bin/compact-windows\r?$', fresh):
            raise ValueError('fresh runtime hash mismatch')
        hashes = {name: digest(out/(name+'.exe')) for name in images}
        for name, sha in hashes.items():
            if not re.search(rb'(?m)^'+sha.encode()+rb'\s+/tmp/cw-'+name.encode()+rb'\.exe\r?$', fresh):
                raise ValueError('native TLS fixture hash mismatch')
        records = parse_cases(fresh, cases)
        if records['api-set']['calls'] != EXPECTED_CALLS:
            raise ValueError('native API-set dispatch counts differ')
        if records['startup-api']['calls'] != STARTUP_CALLS:
            raise ValueError('native startup API dispatch counts differ')
        if records['sync-api']['calls'] != SYNC_CALLS:
            raise ValueError('native synchronization dispatch counts differ')
        if records['sync-blocked']['calls'] != dict(CreateEventA=1,WaitForSingleObject=1):
            raise ValueError('blocking wait silently completed')
        report = dict(schema='compact-windows-w7-native-tls/v1', source_commit=commit,
                      source_archive_sha256=archive_sha, bootstrap_image_sha256=base_sha,
                      kernel_sha256=kernels[0].decode(), runtime_sha256=runtimes[0].decode(),
                      reference=receipt, api_set_reference=api_receipt, fixture_sha256=hashes, cases=records,
                      startup_api_reference=startup_receipt, startup_api_policy=dict(low=LOW_MASK, high=HIGH_MASK),
                      native_startup_state_verified=True,
                      sync_api_reference=sync_receipt, native_sync_state_verified=True,
                      native_api_set_imports_verified=True,
                      native_amd64_qemu_tls_startup_verified=True, jq_execution_verified=False,
                      physical_hardware_qualified=False, full_w7_complete=False)
        (out/'qualification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    finally:
        server.shutdown();server.server_close()


if __name__ == '__main__':
    main()
