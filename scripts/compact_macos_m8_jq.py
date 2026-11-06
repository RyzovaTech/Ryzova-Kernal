# SPDX-License-Identifier: AGPL-3.0-only
"""Capture upstream jq macOS references and measure M6 image admission."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import struct
import subprocess
import tempfile
from urllib.request import urlopen

RELEASE = 'https://github.com/jqlang/jq/releases/download/jq-1.8.1'
TARGETS = {
    'x86_64': ('jq-macos-amd64', 855272, 'e80dbe0d2a2597e3c11c404f03337b981d74b4a8504b70586c354b7697a7c27f', 0x01000007, '--dynamic'),
    'arm64': ('jq-macos-arm64', 841408, 'a9fe3ea2f86dfc72f6728417521ec9067b343277152b114f4e98d8cb0e263603', 0x0100000c, '--arm64'),
}
INPUT = b'{"items":[2,3,5]}\n'
CASES = {
    'version': (['--version'], b'jq-1.8.1\n'),
    'query': (['-c', '{count: (.items | length), sum: (.items | add)}', 'input.json'],
              b'{"count":3,"sum":10}\n'),
}
TOOLS = {'load-commands': ['otool', '-l'], 'libraries': ['otool', '-L'], 'imports': ['nm', '-m', '-u']}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_head():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def verified_image(arch, image):
    _, size, digest, cpu, _ = TARGETS[arch]
    if len(image) != size or sha256(image) != digest:
        raise ValueError(f'{arch}: release binary size or digest mismatch')
    if struct.unpack_from('<3I', image)[:2] != (0xfeedfacf, cpu):
        raise ValueError(f'{arch}: expected thin Mach-O')
    return image


def expected_cases():
    return {name: dict(argv=argv, exit_code=0, stdout_hex=stdout.hex(), stderr_hex='',
                       input_unchanged=True) for name, (argv, stdout) in CASES.items()}


def capture(arch, out):
    if platform.system() != 'Darwin' or platform.machine() != arch:
        raise ValueError(f'{arch}: macOS reference host architecture mismatch')
    out.mkdir(parents=True, exist_ok=True)
    name, size, digest, _, _ = TARGETS[arch]
    binary = (out/name).resolve()
    with urlopen(f'{RELEASE}/{name}', timeout=30) as response:
        binary.write_bytes(verified_image(arch, response.read(size+1)))
    binary.chmod(0o755)
    cases = {}
    for case, (argv, _) in CASES.items():
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)/'input.json'
            path.write_bytes(INPUT)
            run = subprocess.run([binary, *argv], cwd=work, env={'LC_ALL': 'C'},
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            cases[case] = dict(argv=argv, exit_code=run.returncode, stdout_hex=run.stdout.hex(),
                               stderr_hex=run.stderr.hex(), input_unchanged=path.read_bytes()==INPUT)
    if cases != expected_cases():
        raise ValueError(f'{arch}: macOS reference differs: {cases}')
    hashes = {}
    for name, tool in TOOLS.items():
        output = subprocess.check_output([*tool, binary], timeout=15)
        (out/f'{name}.txt').write_bytes(output)
        hashes[name] = sha256(output)
    save_json(out/'reference.json', dict(schema='compact-macos-m8-jq-reference/v1',
              source_commit=source_head(), architecture=arch, platform=platform.platform(),
              sha256=digest, input_sha256=sha256(INPUT), cases=cases, inventory_sha256=hashes))


def audit(references, runner, out, limits):
    commit = source_head()
    results = {}
    for arch, (name, size, digest, _, mode) in TARGETS.items():
        directory = references/f'macos-m8-jq-{arch}'
        binary = directory/name
        verified_image(arch, binary.read_bytes())
        receipt = json.loads((directory/'reference.json').read_text())
        inventory = {key: (directory/f'{key}.txt').read_bytes() for key in TOOLS}
        expected = dict(schema='compact-macos-m8-jq-reference/v1', source_commit=commit,
                        architecture=arch, sha256=digest, input_sha256=sha256(INPUT),
                        cases=expected_cases(), inventory_sha256={k: sha256(v) for k, v in inventory.items()})
        if not str(receipt.get('platform', '')).startswith('macOS-') or any(
                receipt.get(key) != value for key, value in expected.items()):
            raise ValueError(f'{arch}: invalid reference provenance or result')
        run = subprocess.run([runner.resolve(), mode, binary.resolve()], capture_output=True, timeout=10)
        limit = limits[arch]
        if size <= limit or (run.returncode, run.stdout, run.stderr) != (
                125, b'', b'unsupported Mac reference image or execution fault\n'):
            raise ValueError(f'{arch}: unexpected M6 admission result')
        results[arch] = dict(reference=receipt, image_bytes=size, m6_limit_bytes=limit,
                             m6_admission_exit=run.returncode, first_blocker='image-size-limit',
                             version_executed_on_ryzova=False, query_executed_on_ryzova=False)
        print(f'{arch}: macOS references verified; M6 rejects {size} bytes above {limit}')
    out.mkdir(parents=True, exist_ok=True)
    save_json(out/'qualification.json', dict(schema='compact-macos-m8-admission-audit/v1',
              source_commit=commit, architectures=results, upstream_application_qualified=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    ref = commands.add_parser('reference')
    ref.add_argument('arch', choices=TARGETS)
    ref.add_argument('out', type=Path)
    gate = commands.add_parser('audit')
    for arg in ('references', 'runner', 'out'):
        gate.add_argument(arg, type=Path)
    gate.add_argument('x86_limit', type=int)
    gate.add_argument('arm_limit', type=int)
    args = parser.parse_args()
    if args.command == 'reference':
        capture(args.arch, args.out)
    else:
        audit(args.references, args.runner, args.out, {'x86_64': args.x86_limit, 'arm64': args.arm_limit})


if __name__ == '__main__':
    main()
