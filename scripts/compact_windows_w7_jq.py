# SPDX-License-Identifier: AGPL-3.0-only
"""Record a real jq Windows run and audit the same binary's W6 admission."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
URL = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-windows-amd64.exe"
SHA = "23cb60a1354eed6bcc8d9b9735e8c7b388cd1fdcb75726b93bc299ef22dd9334"
SIZE = 1026560
INPUT = b'{"items":[2,3,5]}\n'
STDOUT = b'{"count":3,"sum":10}\n'
ARGS = ["-b", "-c", "{count: (.items | length), sum: (.items | add)}", "input.json"]


def source_head():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_image(image):
    if len(image) != SIZE or sha(image) != SHA:
        raise ValueError("jq executable size or SHA-256 mismatch")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def reference(out):
    if platform.system() != "Windows" or platform.machine().upper() not in ("AMD64", "X86_64"):
        raise ValueError("reference requires Windows AMD64")
    out.mkdir(parents=True, exist_ok=True)
    with urlopen(URL, timeout=30) as response:
        image = response.read(SIZE+1)
    verify_image(image)
    binary = out / "jq.exe"
    binary.write_bytes(image)
    with tempfile.TemporaryDirectory() as work:
        (Path(work) / "input.json").write_bytes(INPUT)
        run = subprocess.run([str(binary.resolve()), *ARGS], cwd=work, capture_output=True,
                             timeout=15, check=False)
    if (run.returncode, run.stdout, run.stderr) != (0, STDOUT, b""):
        raise ValueError(f"jq Windows reference differs: {run!r}")
    write_json(out / "reference.json", {
        "schema": "compact-windows-w7-jq-reference/v1",
        "source_commit": source_head(), "url": URL, "sha256": SHA,
        "platform": platform.platform(), "arch": platform.machine().upper(),
        "argv": ARGS, "input_sha256": sha(INPUT),
        "exit_code": run.returncode, "stdout_hex": run.stdout.hex(),
        "stderr_hex": run.stderr.hex(),
    })


def verify_reference(ref):
    binary = ref / "jq.exe"
    with binary.open("rb") as file:
        verify_image(file.read(SIZE+1))
    receipt = json.loads((ref / "reference.json").read_text(encoding="utf-8"))
    expected = {
        "schema": "compact-windows-w7-jq-reference/v1",
        "source_commit": source_head(), "url": URL, "sha256": SHA,
        "argv": ARGS, "input_sha256": sha(INPUT),
        "exit_code": 0, "stdout_hex": STDOUT.hex(), "stderr_hex": "",
    }
    if (any(receipt.get(key) != value for key, value in expected.items()) or
            receipt.get("arch") not in ("AMD64", "X86_64") or
            not str(receipt.get("platform", "")).startswith("Windows-")):
        raise ValueError("Windows reference receipt mismatch")
    return receipt


def audit(ref, out):
    receipt = verify_reference(ref)
    binary = ref / "jq.exe"
    out.mkdir(parents=True, exist_ok=True)
    runtime = ROOT / "ryzova/compat/windows"
    with tempfile.TemporaryDirectory() as directory:
        probe = Path(directory) / "admission"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                        "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(runtime),
                        str(ROOT / "tests/fixtures/windows_w7_admission.c"),
                        *(str(runtime / name) for name in
                          ("loader.c", "cpu.c", "api.c", "crt.c", "sync_objects.c", "files.c")),
                        "-o", str(probe)], check=True)
        result = json.loads(subprocess.check_output([str(probe), str(binary)], text=True, timeout=5))
    listing = subprocess.check_output(["objdump", "-p", str(binary)], text=True, timeout=5)
    if "file format pei-x86-64" not in listing:
        raise ValueError("jq is not AMD64 PE")
    modules = re.findall(r"^\s*DLL Name: (.+)$", listing, re.M)
    if not modules:
        raise ValueError("missing PE import inventory")
    (out / "pe-inventory.txt").write_text(listing, encoding="utf-8")
    report = {"schema": "compact-windows-w7-jq-audit/v1", "reference": receipt,
              "pe_import_modules": modules, "w6_admission": result,
              "ryzova_execution_verified": False}
    write_json(out / "audit.json", report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("reference", "audit"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    if args.mode == "reference":
        reference(args.out)
    elif args.reference is None:
        parser.error("audit requires --reference")
    else:
        audit(args.reference, args.out)
