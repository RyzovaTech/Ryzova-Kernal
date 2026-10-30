# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 9.1 host-side Compact contract validation; not a native ABI implementation."""
from __future__ import annotations
import re

API_MAJOR = 1
API_MINOR = 0
ENV_RE = re.compile(r"^compact/[a-z][a-z0-9-]{0,31}$")
CAPABILITIES = frozenset({"namespace.read", "process.spawn", "resource.query", "ipc.9p"})

class ContractError(ValueError):
    pass

def negotiate(request: dict) -> dict:
    """Fail closed on unknown majors, malformed requests, and unknown capabilities."""
    if not isinstance(request, dict) or set(request) != {"environment", "api_major", "api_minor", "capabilities"}:
        raise ContractError("invalid request shape")
    env = request["environment"]
    major, minor = request["api_major"], request["api_minor"]
    caps = request["capabilities"]
    if not isinstance(env, str) or not ENV_RE.fullmatch(env):
        raise ContractError("invalid environment identifier")
    if type(major) is not int or major != API_MAJOR:
        raise ContractError("unsupported API major")
    if type(minor) is not int or not (0 <= minor <= API_MINOR):
        raise ContractError("unsupported API minor")
    if not isinstance(caps, list) or len(caps) != len(set(map(str, caps))) or any(not isinstance(c, str) or c not in CAPABILITIES for c in caps):
        raise ContractError("invalid capabilities")
    return {"environment": env, "api_major": API_MAJOR, "api_minor": minor, "capabilities": sorted(caps), "abi": "none", "status": "contract-only"}
