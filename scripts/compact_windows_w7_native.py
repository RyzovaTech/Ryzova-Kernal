# SPDX-License-Identifier: AGPL-3.0-only
"""Verify pinned jq and compatibility fixtures on a source-built Ryzova Kernel."""
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

from compact_c1_jq_contract import INPUT_NAME, VERSION_STDOUT
from compact_c2_file_contract import CANARY, CANARY_NAME, CANARY_SHA256, CREATED_NAME, MUTATION_OPERATIONS, PARENT_ESCAPE
from compact_c2_windows_fixture import fixture as mutation_fixture
from compact_c3_remote import FILENAME as REMOTE_FILE, MOUNT as REMOTE_ROOT, mount_commands, payload, route_fixture, transport_evidence
from compact_windows_w2 import ROOT, PREFERRED
from compact_windows_w6_native import bootstrap_provenance, digest, extract_kernel, parse_cases, session, standalone
from compact_windows_w7_tls import tls_fixture, verify_reference
from compact_windows_w7_jq import ARGS as JQ_ARGS, INPUT as JQ_INPUT, verify_reference as verify_jq_reference
from compact_windows_w7_trace import api_grant_words
from compact_windows_w7_imports import verify_reference as verify_import_reference, EXPECTED_CALLS
from compact_windows_w7_startup import verify_reference as verify_startup_reference, EXPECTED_CALLS as STARTUP_CALLS, LOW_MASK, HIGH_MASK
from compact_windows_w7_sync import verify_reference as verify_sync_reference, sync_fixture, EXPECTED_CALLS as SYNC_CALLS, LOW_MASK as SYNC_LOW, HIGH_MASK as SYNC_HIGH


JQ_ROOT = '/tmp/cw-w7-jq'
JQ_INPUT_PATH = JQ_ROOT + '/' + INPUT_NAME
JQ_DENIED = f'jq: error: Could not open file {INPUT_NAME}: Permission denied\n'.encode()
JQ_ESCAPE_DENIED = f'jq: error: Could not open file {PARENT_ESCAPE}: Invalid argument\n'.encode()
CANARY_PATH = f'/tmp/{CANARY_NAME}'
JQ_READ_ONLY = 9  # CW_GRANT_READ | CW_GRANT_METADATA
JQ_BUDGET = 16777216


def jq_case(reference, argv, *, root=None):
    # The inner string follows Windows argv quoting. rc receives it as one word.
    command = subprocess.list2cmdline(['jq.exe', *argv])
    rc_command = "'" + command.replace("'", "''") + "'"
    words = api_grant_words()
    extra = ''.join(f' -g {i}:{mask}' for i, mask in enumerate(words) if i >= 2 and mask)
    grant = f'-r {root} -R {JQ_READ_ONLY} ' if root else ''
    args = (f'-P trace -b {JQ_BUDGET} {grant}'
            f'-a {words[0]} -A {words[1]}{extra} -c {rc_command}')
    return dict(image='jq', status=0, code=reference['exit_code'],
                out=reference['stdout_hex'], err=reference['stderr_hex'], args=args)


def verify_jq_io(record, input_size):
    expected = dict(rights=JQ_READ_ONLY, read_bytes=input_size, write_bytes=0,
                    profile=3, stop_import=0, peak_handles=1)
    for key, value in expected.items():
        if record.get(key) != value:
            raise ValueError(f'native jq receipt {key}: expected {value}, got {record.get(key)}')
    if not 0 < record.get('steps', 0) <= JQ_BUDGET:
        raise ValueError('invalid native jq instruction count')
    calls = record.get('calls', {})
    if (calls.get('_wfopen') != 1 or calls.get('fgets', 0) < 1 or
            calls.get('fclose', 0) < 1 or calls.get('fwrite', 0) < 1 or
            calls.get('exit') != 1):
        raise ValueError('native jq did not complete the expected stream and exit path')


def verify_guest_input(log, sha):
    sections = re.split(rb'(?m)^CW_CASE_jq-readonly_(?:BEGIN|END)\r?$', log)
    if len(sections) != 3:
        raise ValueError('missing or duplicate native jq boundary')
    before, case, after = sections
    pattern = rb'(?m)^([0-9a-f]{64})[ \t]+' + re.escape(JQ_INPUT_PATH.encode()) + rb'\r?$'
    if (re.findall(pattern, before), re.findall(pattern, case), re.findall(pattern, after)) != (
            [sha.encode()], [], [sha.encode()]):
        raise ValueError('native jq input hash mismatch before or after execution')
    return case


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
    jq_reference = verify_jq_reference(args.reference)
    images['jq'] = (args.reference/'jq.exe').read_bytes()
    cases['jq-readonly'] = jq_case(jq_reference, JQ_ARGS, root=JQ_ROOT)
    cases['jq-version'] = jq_case(dict(exit_code=0, stdout_hex=VERSION_STDOUT.hex(), stderr_hex=''),
                                  ['-b', '--version'])
    cases['jq-no-grant'] = jq_case(dict(exit_code=2, stdout_hex='', stderr_hex=JQ_DENIED.hex()), JQ_ARGS)
    cases['jq-parent-escape'] = jq_case(dict(exit_code=2, stdout_hex='', stderr_hex=JQ_ESCAPE_DENIED.hex()),
                                         [*JQ_ARGS[:-1], PARENT_ESCAPE], root=JQ_ROOT)
    remote = payload(commit)
    cases['jq-remote'] = jq_case(dict(exit_code=0, stdout_hex=remote.hex(), stderr_hex=''),
                                 ['-b', '-c', '.', REMOTE_FILE], root=REMOTE_ROOT)
    images['mutation'] = mutation_fixture()
    cases['mutation'] = dict(image='mutation', status=0, code=0, out='', err='',
                             args=f'-r {JQ_ROOT} -R {JQ_READ_ONLY}')
    (out/INPUT_NAME).write_bytes(JQ_INPUT)
    (out/CANARY_NAME).write_bytes(CANARY)
    # Keep the serial command short. The full quoted Windows argv and policy
    # travel in a checked guest script instead of through the UART.
    launchers = {}
    for name in ('jq-readonly', 'jq-version', 'jq-no-grant', 'jq-parent-escape', 'jq-remote'):
        launcher = out/f'{name}.rc'
        launcher.write_text(f"/amd64/bin/compact-windows {cases[name]['args']} /tmp/cw-jq.exe\n",
                            encoding='ascii')
        launchers[name] = digest(launcher)
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
        commands.append(f'mkdir -p {JQ_ROOT}; hget http://10.0.2.2:8000/{INPUT_NAME} > {JQ_INPUT_PATH}; sha1sum -2 256 {JQ_INPUT_PATH}')
        commands.append(f'hget http://10.0.2.2:8000/{CANARY_NAME} > {CANARY_PATH}; sha1sum -2 256 {CANARY_PATH}')
        for name in launchers:
            commands.append(f'hget http://10.0.2.2:8000/{name}.rc > /tmp/{name}.rc; sha1sum -2 256 /tmp/{name}.rc')
        with route_fixture(commit) as route:
            for name, spec in cases.items():
                if name == 'jq-remote':
                    commands.extend(mount_commands(route))
                command = (f'rc /tmp/{name}.rc' if name in launchers else
                           f"/amd64/bin/compact-windows {spec.get('args', '')} /tmp/cw-{spec['image']}.exe")
                commands.append(f'echo CW_CASE_{name}_BEGIN; {command}; echo CW_CASE_{name}_END')
            commands.append(f'if(! test -e {JQ_ROOT}/{CREATED_NAME}) echo CW_C2_CREATED_ABSENT')
            commands.append(f'sha1sum -2 256 {JQ_INPUT_PATH} {CANARY_PATH}')
            fresh = session(args.image, commands, out, 'fresh', 180)
            remote_route = transport_evidence(route, commit)
        if b'Ryzova Kernel 0.1.0-dev' not in fresh or b'9front-derived' not in fresh or not standalone(fresh, 'CW_IDENTITY_END'):
            raise ValueError('fresh source-built guest identity')
        if not re.search(rb'(?m)^'+runtimes[0]+rb'\s+/amd64/bin/compact-windows\r?$', fresh):
            raise ValueError('fresh runtime hash mismatch')
        hashes = {name: digest(out/(name+'.exe')) for name in images}
        for name, sha in hashes.items():
            if not re.search(rb'(?m)^'+sha.encode()+rb'\s+/tmp/cw-'+name.encode()+rb'\.exe\r?$', fresh):
                raise ValueError(f'native executable hash mismatch: {name}')
        for name, launcher_sha in launchers.items():
            launcher_path = re.escape(f'/tmp/{name}.rc'.encode())
            launcher_hashes = re.findall(rb'(?m)^([0-9a-f]{64})[ \t]+' + launcher_path + rb'\r?$', fresh)
            if launcher_hashes != [launcher_sha.encode()]:
                raise ValueError(f'native {name} launcher hash mismatch')
        verify_guest_input(fresh, jq_reference['input_sha256'])
        canary_digests = re.findall(rb'(?m)^([0-9a-f]{64})[ \t]+' +
                                    re.escape(CANARY_PATH.encode()) + rb'\r?$', fresh)
        if canary_digests != [CANARY_SHA256.encode()] * 2:
            raise ValueError('native C2 outside canary digest mismatch')
        records = parse_cases(fresh, cases)
        mutation = records['mutation']
        if (mutation.get('rights') != JQ_READ_ONLY or mutation.get('error') != 5 or
                mutation.get('read_bytes') != 0 or mutation.get('write_bytes') != 0 or
                mutation.get('peak_handles') != 1 or not standalone(fresh, 'CW_C2_CREATED_ABSENT') or
                mutation['calls'] != dict(CreateFileW=3, WriteFile=1, GetLastError=3, CloseHandle=1, ExitProcess=1)):
            raise ValueError('native C2 read-only mutation receipt mismatch')
        mutation.update(operations=MUTATION_OPERATIONS, fixture_sha256=hashes['mutation'])
        jq_record = records['jq-readonly']
        verify_jq_io(jq_record, len(JQ_INPUT))
        verify_jq_io(records['jq-remote'], len(remote))
        for name in launchers:
            case, record = cases[name], records[name]
            record.update(stdout_hex=case['out'], stderr_hex=case['err'])
            if name not in ('jq-readonly', 'jq-remote'):
                rights = JQ_READ_ONLY if name == 'jq-parent-escape' else 0
                if record.get('rights') != rights or any(record.get(key) != 0 for key in (
                        'read_bytes', 'write_bytes', 'peak_handles')):
                    raise ValueError(f'native {name} unexpectedly accessed file bytes')
                if record['calls'].get('_wfopen', 0) != int(name != 'jq-version'):
                    raise ValueError(f'native {name} did not take the expected file-open path')
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
                      remote_file_route=remote_route, reference=receipt, api_set_reference=api_receipt, fixture_sha256=hashes, cases=records,
                      startup_api_reference=startup_receipt, startup_api_policy=dict(low=LOW_MASK, high=HIGH_MASK),
                      native_startup_state_verified=True,
                      sync_api_reference=sync_receipt, native_sync_state_verified=True,
                      native_api_set_imports_verified=True,
                      native_amd64_qemu_tls_startup_verified=True, jq_execution_verified=True,
                      jq_reference=jq_reference, jq_input_sha256=jq_reference['input_sha256'],
                      jq_executable_sha256=hashes['jq'], jq_root_rights=JQ_READ_ONLY,
                      jq_launcher_sha256=launchers['jq-readonly'], jq_launcher_sha256_by_case=launchers,
                      native_jq_missing_grant_verified=True, native_jq_parent_escape_denied=True,
                      outside_canary_sha256=CANARY_SHA256,
                      jq_input_unchanged=True, native_jq_query_parity_verified=True,
                      physical_hardware_qualified=False, full_w7_complete=False)
        (out/'qualification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    finally:
        server.shutdown();server.server_close()


if __name__ == '__main__':
    main()
