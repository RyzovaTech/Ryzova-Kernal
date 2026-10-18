# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.0: fail-closed, authenticated *in-process* prototype transport.

HMAC proves test message authenticity, NOT confidentiality. There are deliberately
no sockets or Internet connection methods. Production transport needs peer-auth
TLS, secure key provisioning, revocation and native Ryzova integration.
"""
import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import time


class RemoteDenied(Exception):
    """Access denied, replay detected, malformed packet, or failed trust."""


@dataclass(frozen=True)
class PeerPolicy:
    enabled: bool = False
    peers: frozenset = frozenset()
    operations: frozenset = frozenset()
    max_payload: int = 8192
    max_age_seconds: int = 30


def _canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class Endpoint:
    def __init__(self, identity: str, key: bytes, policy: PeerPolicy, clock=None):
        if not identity or not identity.isascii() or len(identity) > 40:
            raise ValueError("invalid peer identity")
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("test key must contain >=32 bytes")
        if not isinstance(policy, PeerPolicy) or not 0 < policy.max_payload <= 65536:
            raise ValueError("invalid policy")
        self.identity = identity
        self._key = key
        self.policy = policy
        self._clock = clock or time.time
        self._next = 0
        self._received = {}

    def _allow(self, peer, operation):
        if not self.policy.enabled or peer not in self.policy.peers:
            raise RemoteDenied("remote peer disabled or not allowlisted")
        if operation not in self.policy.operations:
            raise RemoteDenied("operation not allowlisted")

    def sign(self, destination: str, direction: str, operation: str, payload: bytes) -> bytes:
        self._allow(destination, operation)
        if direction not in ("request", "response"):
            raise RemoteDenied("invalid direction")
        if not isinstance(payload, bytes) or len(payload) > self.policy.max_payload:
            raise RemoteDenied("oversized or invalid payload")
        self._next += 1
        message = {
            "version": 1, "sender": self.identity, "recipient": destination,
            "direction": direction, "op": operation, "seq": self._next,
            "timestamp": int(self._clock()),
            "body": base64.b64encode(payload).decode("ascii")
        }
        signature = hmac.new(self._key, _canonical(message), hashlib.sha256).hexdigest()
        return _canonical({"message": message, "hmac": signature})

    def verify(self, packet: bytes, direction: str, operation: str) -> bytes:
        if not isinstance(packet, bytes) or len(packet) > self.policy.max_payload * 2 + 1024:
            raise RemoteDenied("oversized packet")
        try:
            wrapper = json.loads(packet)
            message = wrapper["message"]
            mac = wrapper["hmac"]
            sender = message["sender"]
            self._allow(sender, operation)
            if (message["version"] != 1 or message["recipient"] != self.identity or
                message["direction"] != direction or message["op"] != operation or
                not isinstance(message["seq"], int) or isinstance(message["seq"], bool) or
                message["seq"] < 1 or not isinstance(message["timestamp"], int) or
                isinstance(message["timestamp"], bool) or
                not isinstance(mac, str) or len(mac) != 64):
                raise RemoteDenied("invalid authentication envelope")
            expected = hmac.new(self._key, _canonical(message), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, mac):
                raise RemoteDenied("authentication failure")
            age = self._clock() - message["timestamp"]
            if age < -5 or age > self.policy.max_age_seconds:
                raise RemoteDenied("expired request")
            if message["seq"] <= self._received.get(sender, 0):
                raise RemoteDenied("replayed request")
            body = base64.b64decode(message["body"], validate=True)
            if len(body) > self.policy.max_payload:
                raise RemoteDenied("payload quota exceeded")
        except RemoteDenied:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, binascii.Error) as exc:
            raise RemoteDenied("malformed envelope") from exc
        self._received[sender] = message["seq"]
        return body


class LocalAuthenticatedTransport:
    """Synchronous trusted test harness, no socket, no remote-network access."""

    def __init__(self, client: Endpoint, server: Endpoint, handlers: dict):
        if client.identity == server.identity:
            raise ValueError("separate client/server identities required")
        self.client, self.server, self.handlers = client, server, dict(handlers)

    def request(self, operation: str, body: bytes) -> bytes:
        if operation not in self.handlers:
            raise RemoteDenied("unsupported service")
        wire = self.client.sign(self.server.identity, "request", operation, body)
        accepted = self.server.verify(wire, "request", operation)
        result = self.handlers[operation](accepted)
        if not isinstance(result, bytes):
            raise RemoteDenied("service must return bytes")
        response = self.server.sign(self.client.identity, "response", operation, result)
        return self.client.verify(response, "response", operation)
