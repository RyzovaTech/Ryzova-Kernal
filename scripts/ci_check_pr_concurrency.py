# SPDX-License-Identifier: GPL-3.0-only
"""Validate repository-wide GitHub Actions PR supersession safety."""
from pathlib import Path
import argparse

D = chr(36)
GROUP = "group: " + D + "{{ github.workflow }}-" + D + "{{ github.event.pull_request.number || github.run_id }}"
CANCEL = "cancel-in-progress: " + D + "{{ github.event_name == 'pull_request' }}"


def verify(root):
    paths = sorted((Path(root) / ".github" / "workflows").glob("*.yml"))
    if not paths:
        raise ValueError("missing Actions workflows")
    checked, errors, workflow_names = [], [], {}
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        if not any(s.strip() == "pull_request:" for s in lines):
            continue
        names = [s[5:].strip() for s in lines if s.startswith("name:")]
        if len(names) != 1 or not names[0]:
            errors.append(path.name + ": missing or duplicate display name")
        elif names[0].lower() in workflow_names:
            errors.append(path.name + ": display name collision with " + workflow_names[names[0].lower()])
        else:
            workflow_names[names[0].lower()] = path.name
        roots = [i for i, s in enumerate(lines) if s == "concurrency:"]
        if len(roots) != 1:
            errors.append(path.name + ": missing or duplicate root concurrency")
            continue
        values = []
        for line in lines[roots[0]+1:]:
            if line and not line[0].isspace() and not line.startswith("#"):
                break
            values.append(line.strip())
        if GROUP not in values or CANCEL not in values:
            errors.append(path.name + ": PR-scoped cancellation not enforced")
        if "queue: max" in values:
            errors.append(path.name + ": historical revisions may accumulate")
        checked.append(path.name)
    if errors:
        raise ValueError("unsafe Actions workflows:\n"+"\n".join(errors))
    if not checked:
        raise ValueError("no pull_request workflows checked")
    return checked


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("."))
    args=p.parse_args()
    print("PASS:",len(verify(args.root)),"PR workflows use safe supersession")
