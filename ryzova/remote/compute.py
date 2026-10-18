# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.3: allowlisted pure arithmetic task offload prototype.

No arbitrary code/command execution, no OS process creation, no actual network
or additional CPU cores. All outputs are independently recomputed by the client.
"""
import hashlib
import json
from ryzova.remote.trust import RemoteDenied

MAX_VECTOR=256
MAX_ELEMENT=1_000_000
MAX_REQUEST_BYTES=8192


class TaskRejected(Exception):
    pass


class IncorrectRemoteResult(Exception):
    pass


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")


def evaluate(task):
    if not isinstance(task,dict) or task.get("op") not in ("sum_squares","dot"):
        raise TaskRejected("unsupported pure task")
    kind=task["op"]
    if set(task) != ({"op","a"} if kind=="sum_squares" else {"op","a","b"}):
        raise TaskRejected("unexpected job arguments")
    a=task["a"]
    if not isinstance(a,list) or not 1<=len(a)<=MAX_VECTOR:
        raise TaskRejected("vector length quota")
    vectors=[a]
    if kind=="dot":
        b=task["b"]
        if not isinstance(b,list) or len(b)!=len(a):
            raise TaskRejected("dot vector length mismatch")
        vectors.append(b)
    for vec in vectors:
        if any(type(value) is not int or abs(value)>MAX_ELEMENT for value in vec):
            raise TaskRejected("only bounded integer operands allowed")
    if kind=="sum_squares":
        return sum(v*v for v in a)
    return sum(x*y for x,y in zip(a,b))


class PureTaskServer:
    def __init__(self,max_jobs=16):
        if type(max_jobs) is not int or not 1<=max_jobs<=100:
            raise ValueError("bounded job budget required")
        self.remaining = max_jobs

    def handle(self,request):
        if not isinstance(request,bytes) or len(request)>MAX_REQUEST_BYTES:
            raise TaskRejected("request size quota")
        try:
            task=json.loads(request)
        except (TypeError,UnicodeDecodeError,ValueError) as exc:
            raise TaskRejected("invalid JSON task") from exc
        result=evaluate(task)
        if self.remaining <= 0:
            raise TaskRejected("job budget exhausted")
        self.remaining -= 1
        return canonical({
            "result":result,
            "input_sha256":hashlib.sha256(request).hexdigest()
        })


class PureTaskClient:
    def __init__(self,transport):
        self.transport=transport

    def run(self,task):
        expected=evaluate(task)
        request=canonical(task)
        if len(request)>MAX_REQUEST_BYTES:
            raise TaskRejected("request too large")
        response=self.transport.request("compute",request)
        try:
            payload=json.loads(response)
            if (not isinstance(payload,dict) or set(payload)!={"result","input_sha256"} or
                type(payload["result"]) is not int or
                payload["input_sha256"]!=hashlib.sha256(request).hexdigest() or
                payload["result"]!=expected):
                raise IncorrectRemoteResult("remote computation mismatch")
        except (TypeError,ValueError,UnicodeDecodeError,KeyError) as exc:
            raise IncorrectRemoteResult("malformed remote computation result") from exc
        return payload["result"]
