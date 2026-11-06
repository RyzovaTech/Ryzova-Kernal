# SPDX-License-Identifier: GPL-3.0-only
"""Shared byte-exact jq workload for Compact C1."""

RELEASE = "https://github.com/jqlang/jq/releases/download/jq-1.8.1"
INPUT_NAME = "input.json"
INPUT = b'{"items":[2,3,5]}\n'
QUERY = "{count: (.items | length), sum: (.items | add)}"
QUERY_ARGS = ["-c", QUERY, INPUT_NAME]
QUERY_STDOUT = b'{"count":3,"sum":10}\n'
VERSION_STDOUT = b"jq-1.8.1\n"
