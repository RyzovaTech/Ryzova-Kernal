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

from compact_c2_file_contract import CANARY, CANARY_NAME, CANARY_SHA256, CREATED_NAME, MUTATION_OPERATIONS, PARENT_ESCAPE
from phase9_process import FLAGS

ROOT = Path(__file__).resolve().parents[1]
URL = f"{RELEASE}/jq-linux-amd64"
SIZE = 2255816
SHA = "020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d"
GUEST_DIRECTORY = "/home/share"
GUEST_INPUT = f"{GUEST_DIRECTORY}/{INPUT_NAME}"
GUEST_QUERY = [*QUERY_ARGS[:-1], GUEST_INPUT]
DENIED_STDERR = f"jq: error: Could not open file {GUEST_INPUT}: No such file or directory\n".encode()
GUEST_ESCAPE = f"{GUEST_DIRECTORY}/{PARENT_ESCAPE}"
ESCAPE_STDERR = f"jq: error: Could not open file {GUEST_ESCAPE}: No such file or directory\n".encode()
NATIVE_CANARY = f"/tmp/{CANARY_NAME}"
NATIVE_ROOT = "/tmp/c1-share"
NATIVE_JQ = "/tmp/c1-jq"
MUTATION_NAME = "c2-mutation.elf"
NATIVE_MUTATION = f"/tmp/{MUTATION_NAME}"
NATIVE_CASES = {"version": (0, VERSION_STDOUT, b""),
                "query": (0, QUERY_STDOUT, b""),
                "without_input_grant": (2, b"", DENIED_STDERR),
                "parent_escape": (2, b"", ESCAPE_STDERR)}
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
    mount = ["-M", f"r:{GUEST_DIRECTORY}={directory}"]
    cases = {"version": ([], ["--version"]), "query": (mount, GUEST_QUERY),
             "without_input_grant": ([], GUEST_QUERY),
             "parent_escape": (mount, [*QUERY_ARGS[:-1], GUEST_ESCAPE])}
    records = {}
    for name, (grants, argv) in cases.items():
        result = run([runner, "-r", "-b", "16777216", *grants, binary, *argv], directory)
        match = DIAGNOSTICS.search(result.stderr)
        if match is None:
            raise ValueError(f"Compact Linux runner produced no result for {name}: {result!r}")
        status, exited, exit_code, steps, syscalls = map(int, match.groups()[:5])
        stderr = result.stderr[:match.start()]
        record = receipt(argv, result, exit_code if exited else None, stderr)
        record.update(vm_status=status, steps=steps, syscalls=syscalls,
                      last_rip=match[6].decode(), runner_exit_code=result.returncode)
        record["matches_expected"] = (status, exited, exit_code, result.stdout, stderr) == (
            0, 1, *NATIVE_CASES[name])
        records[name] = record
    return records


def fetch_image():
    with urlopen(URL, timeout=30) as response:
        image = response.read(SIZE + 1)
    if len(image) != SIZE or sha(image) != SHA:
        raise ValueError("jq Linux executable size or SHA-256 mismatch")
    return image


def build_mutation(output):
    fixtures = ROOT / "tests/fixtures"
    subprocess.run(["cc", *FLAGS, fixtures / "compact_process_start.S",
                    fixtures / "compact_c2_linux_mutation.c", "-o", output], check=True, timeout=120)
    return sha(output.read_bytes())


def native_fixtures(directory):
    (directory / "c1-jq-amd64").write_bytes(fetch_image())
    (directory / "c1-input.json").write_bytes(INPUT)
    (directory / CANARY_NAME).write_bytes(CANARY)
    return build_mutation(directory / MUTATION_NAME)


def native_commands():
    url = "http://10.0.2.2:8000"
    path = f"{NATIVE_ROOT}/{INPUT_NAME}"
    commands = [
        f"mkdir -p {NATIVE_ROOT}; hget {url}/c1-input.json >{path}",
        f"hget {url}/c1-jq-amd64 >{NATIVE_JQ}; sha1sum -2 256 {NATIVE_JQ} {path}",
        f"hget {url}/{CANARY_NAME} >{NATIVE_CANARY}; sha1sum -2 256 {NATIVE_CANARY}",
        "c1=/amd64/bin/compact-linux",
        f"c1filter='{QUERY_ARGS[1]}'",
    ]
    query = f"-c $c1filter {GUEST_INPUT}"
    cases = (("version", "--version"), ("query", query), ("without_input_grant", query),
             ("parent_escape", f"-c $c1filter {GUEST_ESCAPE}"))
    for name, argv in cases:
        base = f"/tmp/c1-{name}"
        grant = f"-M 'r:{GUEST_DIRECTORY}={NATIVE_ROOT}' " if name in ("query", "parent_escape") else ""
        commands += [
            f"$c1 -r -b 16777216 {grant}{NATIVE_JQ} {argv} >{base}.out >[2]{base}.log",
            f"echo C1_{name}_BEGIN; grep '^COMPACT_LINUX_RESULT ' {base}.log",
            f"grep -v '^COMPACT_(LINUX_RESULT|JOBS_STATS|RESOURCE_STATS) ' {base}.log >{base}.err",
            f"sha1sum -2 256 {base}.out {base}.err; cat {base}.out {base}.err; echo C1_{name}_END",
        ]
    commands += [
        f"hget {url}/{MUTATION_NAME} >{NATIVE_MUTATION}; sha1sum -2 256 {NATIVE_MUTATION}",
        f"$c1 -r -M 'r:{GUEST_DIRECTORY}={NATIVE_ROOT}' {NATIVE_MUTATION} >[2]/tmp/c2-mutation.log",
        "echo C2_LINUX_MUTATION_BEGIN; cat /tmp/c2-mutation.log; echo C2_LINUX_MUTATION_END",
        f"if(! test -e {NATIVE_ROOT}/{CREATED_NAME}) echo C2_LINUX_CREATED_ABSENT",
        f"sha1sum -2 256 {path} {NATIVE_CANARY}", "echo COMPACT_C1_LINUX_DONE",
    ]
    return commands


def inspect_native(serial, commit, mutation_sha):
    def digests(data, path):
        return re.findall(rb"(?m)^([0-9a-f]{64})[ \t]+" + re.escape(path.encode()) + rb"\r?$", data)

    path = f"{NATIVE_ROOT}/{INPUT_NAME}"
    input_digest = sha(INPUT)
    checks = {
        "binary_sha256": digests(serial, NATIVE_JQ) == [SHA.encode()],
        "input_unchanged": digests(serial, path) == [input_digest.encode()] * 2,
        "outside_canary_unchanged": digests(serial, NATIVE_CANARY) == [CANARY_SHA256.encode()] * 2,
        "completed": re.search(rb"(?m)^COMPACT_C1_LINUX_DONE\r?$", serial) is not None,
    }
    cases = {}
    for name, (code, stdout, stderr) in NATIVE_CASES.items():
        base = f"/tmp/c1-{name}"
        label = f"C1_{name}".encode()
        section = re.search(rb"(?ms)^" + label + rb"_BEGIN\r?\n(.*?)^" + label + rb"_END\r?$", serial)
        body = section[1] if section else b""
        state = re.findall(rb"(?m)^COMPACT_LINUX_RESULT status=(\d+) exited=([01]) exit=(\d+) "
                           rb"steps=([1-9]\d*) syscalls=([1-9]\d*)\r?$", body)
        out = digests(body, base + ".out")
        err = digests(body, base + ".err")
        passed = (len(state) == 1 and tuple(map(int, state[0][:3])) == (0, 1, code)
                  and out == [sha(stdout).encode()] and err == [sha(stderr).encode()])
        cases[name] = dict(passed=passed, result=[list(map(int, values)) for values in state],
                           stdout_sha256=[value.decode() for value in out],
                           stderr_sha256=[value.decode() for value in err])
    mutation = re.search(rb"(?ms)^C2_LINUX_MUTATION_BEGIN\r?\n(.*?)^C2_LINUX_MUTATION_END\r?$", serial)
    checks["mutation_fixture_sha256"] = digests(serial, NATIVE_MUTATION) == [mutation_sha.encode()]
    checks["mutation_denied"] = bool(mutation and re.search(
        rb"(?m)^COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=[1-9]\d* syscalls=6\r?$",
        mutation[1]))
    checks["created_absent"] = re.search(rb"(?m)^C2_LINUX_CREATED_ABSENT\r?$", serial) is not None
    return dict(schema="compact-c1-linux-native-jq/v1", mutation_fixture_sha256=mutation_sha,
                mutation_operations=MUTATION_OPERATIONS, source_commit=commit,
                binary_sha256=SHA, input_sha256=input_digest, checks=checks, cases=cases,
                passed=all(checks.values()) and all(case["passed"] for case in cases.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("C1 Linux reference requires Linux x86_64")
    image = fetch_image()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory() as work:
        directory = Path(work)
        share = directory / "share"
        share.mkdir()
        input_path = share / INPUT_NAME
        input_path.write_bytes(INPUT)
        canary_path = directory / CANARY_NAME
        canary_path.write_bytes(CANARY)
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
        mutation = directory / MUTATION_NAME
        mutation_sha = build_mutation(mutation)
        result = run([runner, "-r", "-M", f"r:{GUEST_DIRECTORY}={share}", mutation], share)
        state = DIAGNOSTICS.fullmatch(result.stderr)
        if (result.returncode or result.stdout or not state or
                tuple(map(int, state.groups()[:3])) != (0, 1, 0) or int(state[5]) != 6 or
                (share / CREATED_NAME).exists()):
            raise ValueError(f"Compact Linux read-only mutation probe failed: {result!r}")
        if (input_path.read_bytes(), canary_path.read_bytes(), binary.read_bytes()) != (INPUT, CANARY, image):
            raise ValueError("Compact probe changed a fixture")
    report = dict(schema="compact-c1-linux-jq/v1", source_commit=commit, architecture="x86_64",
                  binary_url=URL, binary_sha256=SHA, input_sha256=sha(INPUT), input_unchanged=True,
                  outside_canary_sha256=CANARY_SHA256, linux_reference=reference_cases,
                  mutation_fixture_sha256=mutation_sha, mutation_operations=MUTATION_OPERATIONS,
                  hosted_compact_interpreter=hosted_cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = json.dumps(report, indent=2) + "\n"
    args.output.write_text(output, encoding="utf-8")
    print(output, end="")
    if not all(case["matches_expected"] for case in hosted_cases.values()):
        raise SystemExit("Compact Linux hosted jq parity failed")


if __name__ == "__main__":
    main()
