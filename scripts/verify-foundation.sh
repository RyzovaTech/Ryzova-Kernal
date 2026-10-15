#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PIN="a0806493926c04ce90d4e4a46961dec30a1054dd"

echo "Verifying Ryzova Kernel Phase 1 source foundation"
git cat-file -e "${PIN}^{commit}"
if ! git merge-base --is-ancestor "$PIN" HEAD; then
  echo "ERROR: pinned 9front commit is not in this branch's history" >&2
  exit 1
fi

for file in \
  lib/legal/NOTICE \
  lib/legal/mit \
  lib/legal/contributing \
  sys/src/9/pc64/mkfile \
  sys/src/9/pc64/main.c \
  sys/src/9/port/page.c \
  docs/UPSTREAM.md \
  docs/BUILD.md \
  docs/LICENSE-REVIEW.md; do
  if ! test -s "$file"; then
    echo "ERROR: missing or empty required file: $file" >&2
    exit 1
  fi
done

grep -q "MIT" lib/legal/NOTICE
grep -q "Permission is hereby granted" lib/legal/mit
printf 'Pinned upstream commit: %s\n' "$PIN"
printf 'Current Ryzova commit: %s\n' "$(git rev-parse HEAD)"
echo 'PASS: provenance, required source files, and license notices present.'
echo 'NOTE: this test DOES NOT compile or boot the kernel.'
