# SPDX-License-Identifier: GPL-3.0-only
"""Cross-platform Compact file capability fixture."""

import hashlib

CANARY_NAME = "c2-canary.json"
CREATED_NAME = "c2-created.json"
CANARY = b'{"items":[997]}\n'
CANARY_SHA256 = hashlib.sha256(CANARY).hexdigest()
PARENT_ESCAPE = f"../{CANARY_NAME}"
MUTATION_OPERATIONS = ("write", "create", "truncate")
