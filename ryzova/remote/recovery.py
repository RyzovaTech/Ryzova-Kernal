# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.4 opt-in failure containment and privacy-minimal telemetry.

Host-side prototype only: a synchronous call cannot be interrupted here.
Phase 6.5's real socket implementation applies its own network timeout.
"""
from collections import Counter, deque
import time

class ServiceUnavailable(Exception):
    pass

class DeadlineExceeded(ServiceUnavailable):
    pass

class RemoteCircuit:
    def __init__(self, transport, *, enabled=False, failure_threshold=2,
                 cooldown_seconds=5.0, deadline_seconds=1.0, clock=None,
                 event_capacity=32):
        if not (type(failure_threshold) is int and 1 <= failure_threshold <= 16 and
                0.01 <= cooldown_seconds <= 3600 and
                0.01 <= deadline_seconds <= 30 and
                type(event_capacity) is int and 1 <= event_capacity <= 128):
            raise ValueError("invalid bounded circuit policy")
        self.transport = transport
        self.enabled = enabled
        self.threshold = failure_threshold
        self.cooldown = cooldown_seconds
        self.deadline = deadline_seconds
        self.clock = clock or time.monotonic
        self.events = deque(maxlen=event_capacity)
        self.counters = Counter()
        self.consecutive_failures = 0
        self.blocked_until = 0.0
        self._trial = False

    def _record(self, operation, category):
        # Operation from an allowlist; never retain payload, addresses or exception text.
        self.counters[category] += 1
        self.events.append((operation, category))

    def request(self, operation, payload):
        if operation not in ("9p", "page", "compute"):
            raise ServiceUnavailable("operation not allowlisted")
        if not self.enabled:
            self._record(operation, "disabled")
            raise ServiceUnavailable("service disabled")
        now = self.clock()
        if now < self.blocked_until:
            self._record(operation, "circuit_open")
            raise ServiceUnavailable("circuit open")
        if self._trial:
            self._record(operation, "probe_busy")
            raise ServiceUnavailable("only one recovery probe")
        if not isinstance(payload, bytes) or len(payload) > 8192:
            self._record(operation, "rejected")
            raise ServiceUnavailable("request quota")
        self._trial = True
        try:
            result = self.transport.request(operation, payload)
            if self.clock() - now > self.deadline:
                raise DeadlineExceeded("operation exceeded deadline")
            if not isinstance(result, bytes) or len(result) > 8192:
                raise ServiceUnavailable("unbounded service response")
        except Exception as exc:
            self.consecutive_failures += 1
            self._record(operation, "failure")
            if self.consecutive_failures >= self.threshold:
                self.blocked_until = self.clock() + self.cooldown
                self._record(operation, "circuit_trip")
            raise ServiceUnavailable("remote request failed closed") from exc
        finally:
            self._trial = False
        self.consecutive_failures = 0
        self.blocked_until = 0.0
        self._record(operation, "success")
        return result

    def telemetry(self):
        return {
            "enabled": self.enabled,
            "counters": dict(self.counters),
            "events": [list(pair) for pair in self.events],
            "open": self.clock() < self.blocked_until
        }
