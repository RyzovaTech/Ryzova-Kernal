# SPDX-License-Identifier: GPL-3.0-only
"""Record Linux reference and hosted Compact interpreter results for C1."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from urllib.request import urlopen

from compact_c1_jq_contract import INPUT, INPUT_NAME, QUERY_ARGS, QUERY_STDOUT, RELEASE, VERSION_STDOUT

ROOT = Path(__file__).resolve().parents[1]
URL = f"{RELEASE}/jq-linux-amd64"
SIZE = 2255816
SHA = "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d"
GUEST_DIRECTORY = "/home/share"
SOURCES = ("elf64", "namespace", "syscall", "subset_vm", "memory", "process", "cpu", "jobs", "jobs_probe")
DIAGNOSTICS = re.compile(
    rb"(?m)^COMPACT_JOBS_RESULT status=(\d+) exited=([01]) exit=(\d+) steps=(\d+) "
    rb"syscalls=(\d+) [^\n]* rip=([0-9a-f]+)\nCOMPACT_RESOURCE_STATS [^\n]+\n\Z"
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(command, cwd):
    return subprocess.run(command, cwd=cwd, capture_output=True, timeout=45)


def receipt(argv, result, status, stderr):
    return dict(argv=argv, exit_code=status, stdout_hex=result.stdout.hex(), stderr_hex=stderr.hex())


def reference(binary, directory):
    cases = {"version": (["--version"], VERSION_STDOUT), "query": (QUERY_ARGS, QUERY_STDOUT)}
    records = {}
    for name, (argv, expected) in cases.items():
        result = run([binary, *argv], directory)
        if (result.returncode, result.stdout, result.stderr) != (0, expected, b""):
            raise ValueError(f"Linux reference {name} differs: {result!r}")
        records[name] = receipt(argv, result, result.returncode, result.stderr)
    return records


def probe(runner, binary, directory):
    guest_query = [*QUERY_ARGS[:-1], f"{GUEST_DIRECTORY}/{INPUT_NAME}"]
    mount = ["-M", f"r:{GUEST_DIRECTORY}={directory}"]
    cases = {"version": ([], ["--version"], VERSION_STDOUT),
             "query": (mount, guest_query, QUERY_STDOUT),
             "without_input_grant": ([], guest_query, None)}
    records = {}
    for name, (grants, argv, expected) in cases.items():
        result = run([runner, "-r", "-b", "16777216", *grants, binary, *argv], directory)
        match = DIAGNOSTICS.search(result.stderr)
        if match is None:
            raise ValueError(f"Compact Linux runner produced no result for {name}: {result!r}")
        status, exited, exit_code, steps, syscalls = map(int, match.groups()[:5])
        stderr = result.stderr[:match.start()]
        record = receipt(argv, result, exit_code if exited else None, stderr)
        record.update(vm_status=status, steps=steps, syscalls=syscalls,
                      last_rip=match[6].decode(), runner_exit_code=result.returncode)
        if expected is not None:
            record["matches_reference"] = (status, exited, exit_code, result.stdout, stderr) == (
                0, 1, 0, expected, b"")
        records[name] = record
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("C1 Linux reference requires Linux x86_64")
    with urlopen(URL, timeout=30) as response:
        image = response.read(SIZE + 1)
    if len(image) != SIZE or sha(image) != SHA:
        raise ValueError("jq Linux executable size or SHA-256 mismatch")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory() as work:
        directory = Path(work)
        share = directory / "share"
        share.mkdir()
        input_path = share / INPUT_NAME
        input_path.write_bytes(INPUT)
        binary = directory / "jq"
        binary.write_bytes(image)
        binary.chmod(0o700)
        reference_cases = reference(binary, share)
        runner = directory / "compact-linux-jobs"
        source = ROOT / "ryzova/compat/linux"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
                        *(source / f"{name}.c" for name in SOURCES), "-o", runner],
                       check=True, timeout=120)
        hosted_cases = probe(runner, binary, share)
        if input_path.read_bytes() != INPUT or binary.read_bytes() != image:
            raise ValueError("C1 probe changed the pinned executable or input")
    report = dict(schema="compact-c1-linux-jq/v1", source_commit=commit, architecture="x86_64",
                  binary_url=URL, binary_sha256=SHA, input_sha256=sha(INPUT), input_unchanged=True,
                  linux_reference=reference_cases, hosted_compact_interpreter=hosted_cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = json.dumps(report, indent=2) + "\n"
    args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
