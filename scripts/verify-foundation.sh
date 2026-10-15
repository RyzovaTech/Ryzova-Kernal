#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
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
# The successful official 9front nightly builder recorded source SHA 9c754397....
# The difference to the Ryzova-pinned upstream baseline is only an unrelated game file.
UPSTREAM_BUILT_SHA="9c7543976c3e9614ddd61c1173aaa754aff5e1d5"
git cat-file -e "${UPSTREAM_BUILT_SHA}^{commit}"
parity_diff="$(git diff --name-only "$UPSTREAM_BUILT_SHA" "$PIN")"
if [ "$parity_diff" != "sys/src/games/aout2gba.c" ]; then
  echo "ERROR: upstream prebuilt baseline differs from pinned kernel source beyond the expected games file." >&2
  printf 'Changed files:\n%s\n' "$parity_diff" >&2
  exit 1
fi
echo "PASS: imported kernel source unchanged from official 9front nightly builder baseline ($UPSTREAM_BUILT_SHA)."
echo "NOTE: this proves source parity, NOT independent Ryzova kernel compilation or boot."

printf 'Pinned upstream commit: %s\n' "$PIN"
printf 'Current Ryzova commit: %s\n' "$(git rev-parse HEAD)"
echo 'PASS: provenance, required source files, and license notices present.'
echo 'NOTE: this test DOES NOT compile or boot the kernel.'
