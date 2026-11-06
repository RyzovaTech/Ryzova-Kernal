# SPDX-License-Identifier: AGPL-3.0-only
"""Verify Compact macOS M8 version and JSON query output after booting the source-built guest."""
import argparse
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tarfile
import threading

from compact_macos_m2_native import digest_line
from compact_macos_m8_jq import INPUT, TARGETS, expected_cases, source_head, verified_image
from compact_windows_w6_native import bootstrap_provenance, extract_kernel, session


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(image, bootstrap, references, output):
    base_sha = bootstrap_provenance(image, bootstrap)
    output.mkdir(parents=True, exist_ok=True)
    commit = source_head()
    cases_by_arch = {}
    (output/'input.json').write_bytes(INPUT)
    for arch, (name, _, digest, _, _) in TARGETS.items():
        ref = references/f'macos-m8-jq-{arch}'
        (output/name).write_bytes(verified_image(arch, (ref/name).read_bytes()))
        receipt = json.loads((ref/'reference.json').read_text())
        cases = receipt['cases']
        if (receipt['source_commit'], receipt['sha256'], receipt['architecture'], cases) != (
                commit, digest, arch, expected_cases()):
            raise ValueError(f'{arch}: native reference evidence mismatch')
        cases_by_arch[arch] = cases

    sources = subprocess.check_output(
        ['git', 'ls-files', '-z', 'sys/src/9', 'sys/include', 'amd64/include',
         'ryzova/compat/macos', 'ryzova/compat/windows'], text=True)
    archive = output/'source.tgz'
    with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
        for source in sources.rstrip('\0').split('\0'):
            target = source.replace('ryzova/compat/', 'sys/src/cmd/compact-m8/', 1)
            tar.add(source, arcname=target, recursive=False)
    source_sha = sha256(archive)

    setup = 'ip/ipconfig -d ether /net/ether0; webfs'
    url = 'http://10.0.2.2:8000'
    program = '/amd64/bin/compact-macos-m8'
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(output))
    with ThreadingHTTPServer(('127.0.0.1', 8000), handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            build = session(image, [
                setup,
                f'hget {url}/source.tgz > /tmp/m8-source.tgz; sha1sum -2 256 /tmp/m8-source.tgz',
                'cd /; tar xzf /tmp/m8-source.tgz',
                'cd /sys/src/cmd/compact-m8/macos; '
                'rc m8_build.rc >/tmp/m8-build.log >[2=1] && echo M8_NATIVE_OK; cat /tmp/m8-build.log',
                'cd /sys/src/9/pc64; mk >/tmp/m8-kernel.log >[2=1] && echo M8_KERNEL_OK; tail -n 25 /tmp/m8-kernel.log',
                '9fs 9fat; cd /sys/src/9/pc64; cp 9pc64 /n/9fat/9pc64 && cmp 9pc64 /n/9fat/9pc64 '
                '&& echo M8_COPY_OK; sha1sum -2 256 9pc64',
                f'sha1sum -2 256 {program}; echo sync >> /srv/hjfs.cmd; sleep 3',
            ], output, 'build', 850, {3:'M8_NATIVE_OK', 4:'M8_KERNEL_OK', 5:'M8_COPY_OK'})
            if digest_line(build, '/tmp/m8-source.tgz') != source_sha:
                raise ValueError('native source archive differs')
            kernel_sha = digest_line(build, '9pc64')
            extract_kernel(image, output, kernel_sha)
            runner_sha = digest_line(build, program)
            commands = [
                f"cat '#Z/version'; sha1sum -2 256 {program}", setup,
                f'hget {url}/input.json >/tmp/m8-input; cp /tmp/m8-input /tmp/m8-input-original',
                'sha1sum -2 256 /tmp/m8-input-original',
            ]
            markers = {}
            for arch, (name, *_details) in TARGETS.items():
                path = f'/tmp/m8-{arch}'
                commands.append(f'hget {url}/{name} > {path}; sha1sum -2 256 {path}')
                for case in ('version', 'query'):
                    prefix = f'{path}-{case}'
                    marker = f'M8_{arch}_{case}_OK'
                    markers[len(commands)] = marker
                    argument = ' /tmp/m8-input' if case == 'query' else ''
                    commands.append(
                        f'{program} --{case} {path}{argument} >{prefix}.out >[2]{prefix}.err && echo {marker}')
                    commands.append(f'sha1sum -2 256 {prefix}.out {prefix}.err')
            commands.append('sha1sum -2 256 /tmp/m8-input')
            run = session(image, commands, output, 'fresh', 120, markers)
        finally:
            server.shutdown()

    if b'Ryzova Kernel' not in run or digest_line(run, program) != runner_sha:
        raise ValueError('native kernel or runtime identity differs')
    input_digest = hashlib.sha256(INPUT).hexdigest()
    if any(digest_line(run, name) != input_digest for name in ('/tmp/m8-input-original', '/tmp/m8-input')):
        raise ValueError('native input digest changed')
    report = {}
    for arch, (name, _, digest, _, _) in TARGETS.items():
        path = f'/tmp/m8-{arch}'
        if digest_line(run, path) != digest:
            raise ValueError(f'{arch}: in-guest executable digest differs')
        for case, reference in cases_by_arch[arch].items():
            for stream, suffix in (('stdout', 'out'), ('stderr', 'err')):
                expected_digest = hashlib.sha256(bytes.fromhex(reference[f'{stream}_hex'])).hexdigest()
                if digest_line(run, f'{path}-{case}.{suffix}') != expected_digest:
                    raise ValueError(f'{arch}: native {case} {stream} differs')
        report[arch] = dict(sha256=digest, cases=cases_by_arch[arch])
    receipt = dict(schema='compact-macos-m8-native-jq/v1', source_commit=commit,
                   source_archive_sha256=source_sha, bootstrap_sha256=base_sha, kernel_sha256=kernel_sha,
                   runner_sha256=runner_sha, host_architecture='amd64', architectures=report,
                   input_sha256=input_digest, input_unchanged=True, jq_profile_qualified=True)
    (output/'qualification.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'bootstrap', 'references', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    verify(args.image, args.bootstrap, args.references, args.output)
