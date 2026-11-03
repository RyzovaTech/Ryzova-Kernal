# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.0: default-deny, host-only 9P research identity and scope policy.

This is a secondary authorization policy, NOT a TLS certificate verifier.
The caller must already have authenticated the TLS peer and obtained its
verified leaf DER certificate. No native guest identity lifecycle, real
certificate revocation service, or production PKI is implemented here.
"""
from dataclasses import dataclass
import hashlib
import hmac
import re


_PIN = re.compile(r"[0-9a-f]{64}\Z")
_PEER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_FILE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class TrustDenied(Exception):
    """Generic failure: never include certificate, file path or private data."""


@dataclass(frozen=True)
class PeerGrant:
    peer_id: str
    cert_sha256: str
    expires_at: int
    files: tuple[str, ...] = ("probe",)

    def __post_init__(self):
        if not isinstance(self.peer_id, str) or not _PEER.fullmatch(self.peer_id):
            raise ValueError("invalid peer identity")
        if not isinstance(self.cert_sha256, str) or not _PIN.fullmatch(self.cert_sha256):
            raise ValueError("invalid pinned DER SHA256")
        if type(self.expires_at) is not int or not 1 <= self.expires_at <= 253402300799:
            raise ValueError("invalid trust policy expiry")
        if (type(self.files) is not tuple or not 1 <= len(self.files) <= 16
                or any(type(name) is not str or not _FILE.fullmatch(name)
                       or name in (".", "..") for name in self.files)):
            raise ValueError("only bounded flat, unprivileged 9P file scopes")
        if len(set(self.files)) != len(self.files):
            raise ValueError("duplicate file grants")


@dataclass(frozen=True)
class ResearchTrustPolicy:
    """Immutable test-policy snapshots; explicit admin changes increment generation."""

    peers: tuple[PeerGrant, ...] = ()
    revoked_sha256: frozenset[str] = frozenset()
    generation: int = 1
    enabled: bool = False

    def __post_init__(self):
        if (type(self.enabled) is not bool or type(self.generation) is not int
                or not 1 <= self.generation <= 2**63 - 1):
            raise ValueError("invalid policy state")
        if (type(self.peers) is not tuple or len(self.peers) > 16
                or any(type(p) is not PeerGrant for p in self.peers)):
            raise ValueError("invalid peer grant collection")
        if (len({p.peer_id for p in self.peers}) != len(self.peers)
                or len({p.cert_sha256 for p in self.peers}) != len(self.peers)):
            raise ValueError("ambiguous peer identity")
        if (type(self.revoked_sha256) is not frozenset
                or len(self.revoked_sha256) > 128
                or any(type(v) is not str or not _PIN.fullmatch(v)
                       for v in self.revoked_sha256)):
            raise ValueError("invalid revocation collection")

    def authorize_read(self, *, peer_id, cert_der, path, byte_count,
                       now, tls_authenticated, tls_version):
        """Allow bounded read only after independently verified TLS + leaf pin.

        'tls_authenticated' is an assertion from the TLS transport adapter,
        NOT cryptographic proof when supplied by an untrusted caller. Never
        expose this raw method as an unauthenticated network authorization API.
        """
        if (not self.enabled or tls_authenticated is not True
                or tls_version not in ("TLSv1.2", "TLSv1.3")
                or type(peer_id) is not str or type(cert_der) is not bytes
                or not cert_der or len(cert_der) > 16384
                or type(path) is not str or type(byte_count) is not int
                or not 1 <= byte_count <= 4096
                or type(now) is not int or now < 0):
            raise TrustDenied("remote read denied")
        grant = next((p for p in self.peers if p.peer_id == peer_id), None)
        if grant is None or now >= grant.expires_at or path not in grant.files:
            raise TrustDenied("remote read denied")
        actual = hashlib.sha256(cert_der).hexdigest()
        if (actual in self.revoked_sha256
                or not hmac.compare_digest(actual, grant.cert_sha256)):
            raise TrustDenied("remote read denied")
        return True

    def revoke_peer(self, peer_id, *, new_generation):
        """Offline policy update; not certificate-authority CRL/OCSP."""
        self._check_generation(new_generation)
        grant = self._find(peer_id)
        if grant.cert_sha256 in self.revoked_sha256:
            raise ValueError("peer pin already revoked")
        return ResearchTrustPolicy(
            peers=self.peers,
            revoked_sha256=self.revoked_sha256 | {grant.cert_sha256},
            generation=new_generation,
            enabled=self.enabled,
        )

    def rotate_pin(self, peer_id, new_cert_sha256, *, new_generation):
        """Offline admin-controlled rotation; old fingerprint remains revoked."""
        self._check_generation(new_generation)
        if type(new_cert_sha256) is not str or not _PIN.fullmatch(new_cert_sha256):
            raise ValueError("exact new DER SHA256 required")
        grant = self._find(peer_id)
        if (new_cert_sha256 == grant.cert_sha256
                or new_cert_sha256 in self.revoked_sha256
                or any(p.cert_sha256 == new_cert_sha256 for p in self.peers)):
            raise ValueError("rotation requires a fresh non-revoked unique pin")
        replacement = PeerGrant(grant.peer_id, new_cert_sha256, grant.expires_at, grant.files)
        return ResearchTrustPolicy(
            peers=tuple(replacement if p.peer_id == peer_id else p for p in self.peers),
            revoked_sha256=self.revoked_sha256 | {grant.cert_sha256},
            generation=new_generation,
            enabled=self.enabled,
        )

    def _check_generation(self, new_generation):
        if (type(new_generation) is not int
                or new_generation != self.generation + 1):
            raise ValueError("policy generation must increase by exactly one")

    def _find(self, peer_id):
        grant = next((p for p in self.peers if p.peer_id == peer_id), None)
        if grant is None:
            raise ValueError("unknown peer")
        return grant
