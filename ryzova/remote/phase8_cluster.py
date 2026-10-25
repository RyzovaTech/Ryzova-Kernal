# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.2.0 — default-disabled Ryzova distributed resource *control plane*.

Host-only reference scheduler. No remote socket, native guest scheduler,
9P mount, executable transfer, sandbox or physical CPU/RAM pooling exists.
The registered handlers are pre-installed, trusted IN-PROCESS test adapters.
Node-offer fingerprints are admission metadata, not cryptographic proof:
a separately authenticated TLS channel must supply peer identity in future.
"""
from dataclasses import dataclass
import hashlib
import hmac
import re


_NODE_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_PIN = re.compile(r"[0-9a-f]{64}\Z")
_ROLES = frozenset(("compute", "storage", "gpu", "device", "cache"))
_ARCHES = frozenset(("amd64", "arm64"))
_OPS = frozenset(("sha256", "byte_count"))


class ResourceDenied(Exception):
    """No eligible resource, missing authorization or invalid result."""


@dataclass(frozen=True)
class NodeOffer:
    node_id: str
    cert_pin: str
    roles: frozenset[str]
    architectures: frozenset[str]
    slots: int
    busy: int
    latency_ms: int
    lease_until: int
    generation: int = 1
    local: bool = False
    max_payload: int = 4096

    def __post_init__(self):
        if type(self.node_id) is not str or not _NODE_ID.fullmatch(self.node_id):
            raise ValueError("invalid node identity")
        if type(self.cert_pin) is not str or not _PIN.fullmatch(self.cert_pin):
            raise ValueError("invalid node certificate pin")
        if type(self.roles) is not frozenset or not self.roles or not self.roles <= _ROLES:
            raise ValueError("invalid resource roles")
        if (type(self.architectures) is not frozenset or not self.architectures
                or not self.architectures <= _ARCHES):
            raise ValueError("invalid architectures")
        if (type(self.slots) is not int or not 1 <= self.slots <= 64
                or type(self.busy) is not int or not 0 <= self.busy <= self.slots
                or type(self.latency_ms) is not int or not 0 <= self.latency_ms <= 10000
                or type(self.lease_until) is not int or not 1 <= self.lease_until <= 253402300799
                or type(self.generation) is not int or not 1 <= self.generation <= 2**63 - 1
                or type(self.local) is not bool
                or type(self.max_payload) is not int or not 1 <= self.max_payload <= 4096):
            raise ValueError("invalid bounded node capacity")

    @property
    def namespace(self):
        """A proposed name only; this does NOT create a 9P mount."""
        return "/cluster/nodes/" + self.node_id


@dataclass(frozen=True)
class Workload:
    """Only tiny, deterministic, side-effect-free research operations."""

    kind: str
    payload: bytes
    architecture: str = "any"
    allow_remote: bool = False

    def __post_init__(self):
        if type(self.kind) is not str or self.kind not in _OPS:
            raise ValueError("unsupported workload kind")
        if type(self.payload) is not bytes or not 0 < len(self.payload) <= 4096:
            raise ValueError("only 1..4096 bytes of public test data")
        if type(self.architecture) is not str or self.architecture not in (_ARCHES | {"any"}):
            raise ValueError("unsupported architecture")
        if type(self.allow_remote) is not bool:
            raise ValueError("remote execution must be an explicit opt-in")


@dataclass(frozen=True)
class TaskReceipt:
    node_id: str
    operation: str
    result: str | int
    attempts: int


class ResourceRegistry:
    """Explicit admin allowlist; never accept offers directly from untrusted 9P."""

    def __init__(self, pinned_nodes=None, *, enabled=False):
        if type(enabled) is not bool or type(pinned_nodes) not in (dict, type(None)):
            raise ValueError("invalid registry configuration")
        pins = {} if pinned_nodes is None else dict(pinned_nodes)
        if (len(pins) > 16 or any(type(k) is not str or not _NODE_ID.fullmatch(k)
                                  or type(v) is not str or not _PIN.fullmatch(v)
                                  for k, v in pins.items())):
            raise ValueError("invalid static node allowlist")
        self.enabled = enabled
        self._pins = pins
        self._offers = {}
        self._quarantined = set()

    def admit(self, offer, *, presented_fingerprint, now):
        """For TRUSTED control-plane use only; fingerprints alone are spoofable.

        Future integration must derive the identity and DER fingerprint from a
        verified TLS channel and enforce admin authorization before calling.
        """
        if (not self.enabled or type(offer) is not NodeOffer
                or type(presented_fingerprint) is not str
                or type(now) is not int or now < 0):
            raise ResourceDenied("node admission denied")
        expected = self._pins.get(offer.node_id)
        if (expected is None or not _PIN.fullmatch(presented_fingerprint)
                or not hmac.compare_digest(expected, presented_fingerprint)
                or not hmac.compare_digest(expected, offer.cert_pin)
                or offer.lease_until <= now or offer.node_id in self._quarantined):
            raise ResourceDenied("node admission denied")
        previous = self._offers.get(offer.node_id)
        if previous is not None and offer.generation <= previous.generation:
            raise ResourceDenied("stale node generation")
        self._offers[offer.node_id] = offer

    def quarantine(self, node_id):
        """Fail-closed until a *new trusted registry instance* is provisioned."""
        if node_id in self._pins:
            self._quarantined.add(node_id)
            self._offers.pop(node_id, None)

    def offers(self, now):
        if not self.enabled or type(now) is not int or now < 0:
            return ()
        return tuple(o for o in self._offers.values()
                     if o.lease_until > now and o.node_id not in self._quarantined)


class UnifiedCoordinator:
    """Deterministic automatic node choice; trusted in-process adapters ONLY."""

    def __init__(self, registry, handlers, *, enabled=False):
        if (type(registry) is not ResourceRegistry or type(handlers) is not dict
                or type(enabled) is not bool
                or len(handlers) > 16
                or any(type(k) is not str or not callable(v)
                       for k, v in handlers.items())):
            raise ValueError("invalid research coordinator")
        self.registry = registry
        self.enabled = enabled
        self._handlers = dict(handlers)
        self._reserved = {}

    def choices(self, job, *, now, exclude=frozenset()):
        if not self.enabled or not self.registry.enabled or type(job) is not Workload:
            raise ResourceDenied("distributed compute disabled")
        if type(now) is not int or now < 0:
            raise ResourceDenied("invalid request time")
        eligible = []
        for node in self.registry.offers(now):
            if (node.node_id in exclude or "compute" not in node.roles
                    or node.node_id not in self._handlers
                    or (not node.local and not job.allow_remote)
                    or job.architecture not in ("any", *node.architectures)
                    or len(job.payload) > node.max_payload):
                continue
            used = node.busy + self._reserved.get(node.node_id, 0)
            if used >= node.slots:
                continue
            # Free capacity is preferred over a busy node, then lower latency;
            # tie-break by node name so scheduling is deterministic.
            eligible.append(((used / node.slots, node.latency_ms, node.node_id), node))
        return tuple(node for _, node in sorted(eligible, key=lambda item: item[0]))

    def submit(self, job, *, now, max_attempts=2):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 2:
            raise ValueError("only bounded retry for pure operations")
        tried = set()
        for attempt in range(1, max_attempts + 1):
            choices = self.choices(job, now=now, exclude=frozenset(tried))
            if not choices:
                break
            node = choices[0]
            tried.add(node.node_id)
            self._reserved[node.node_id] = self._reserved.get(node.node_id, 0) + 1
            try:
                value = self._handlers[node.node_id](job.kind, job.payload)
                if job.kind == "sha256":
                    valid = type(value) is str and bool(_PIN.fullmatch(value))
                else:
                    valid = type(value) is int and 0 <= value <= len(job.payload)
                if not valid:
                    raise ResourceDenied("untrusted task response")
                return TaskReceipt(node.node_id, job.kind, value, attempt)
            except Exception:
                # Bad/failed trusted adapter is never silently retried on the
                # same node. This is not proof of a secure remote executor.
                self.registry.quarantine(node.node_id)
            finally:
                self._reserved[node.node_id] -= 1
        raise ResourceDenied("no authorized node successfully completed task")


def public_pure_handler(kind, payload):
    """Trusted local test adapter, not a remotely executable code payload."""
    if kind == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if kind == "byte_count":
        return len(payload)
    raise ResourceDenied("unsupported operation")
