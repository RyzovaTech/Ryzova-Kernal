# SPDX-License-Identifier: AGPL-3.0-only
"""Ephemeral fixture for localhost native QEMU 9P -> mutually TLS peer tests."""
from contextlib import AbstractContextManager
import hashlib
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading

from ryzova.remote.native_bridge import SecureReadOnly9PPeer, Local9PTLSGateway
from ryzova.remote.native_guest_tls import NativeGuestTLS12Endpoint
from ryzova.remote.tlsloop import server_context, client_context


def _cert(directory, name):
    path = Path(directory)
    certificate, key = path/(name + ".pem"), path/(name + ".key")
    args = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-sha256", "-days", "1",
            "-subj", "/CN=" + ("localhost" if name == "server" else "ryzova-gateway"),
            "-keyout", str(key), "-out", str(certificate)]
    if name == "server":
        args.extend(["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
    subprocess.run(args, check=True, capture_output=True, timeout=30)
    return certificate, key


def _pin(certificate):
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="utf-8"))
    ).hexdigest()


class Ephemeral9PTLSFixture(AbstractContextManager):
    def __init__(self, public_payload, gateway_port=0, guest_tls_port=0,
                 max_guest_sessions=8, max_guest_frames=256,
                 research_policy_factory=None):
        if not isinstance(public_payload, bytes) or not 0 < len(public_payload) <= 4096:
            raise ValueError("only one small public test fixture allowed")
        if (type(max_guest_sessions) is not int or
                not 1 <= max_guest_sessions <= 32):
            raise ValueError("guest TLS session limit must be 1..32")
        if (type(max_guest_frames) is not int or
                not 1 <= max_guest_frames <= 4096):
            raise ValueError("guest 9P frame limit must be 1..4096")
        self.payload = public_payload
        self.gateway_port = gateway_port
        self.guest_tls_port = guest_tls_port
        self.max_guest_sessions = max_guest_sessions
        self.max_guest_frames = max_guest_frames
        if research_policy_factory is not None and not callable(research_policy_factory):
            raise ValueError("policy factory must be callable")
        self.research_policy_factory = research_policy_factory
        self.guest_cert_sha256 = None
        self._guest_tls = None
        self._directory = None
        self._peer = None
        self._gateway = None
        self._threads = []
        self._started_listeners = []

    @property
    def peer(self):
        return self._peer

    @property
    def gateway(self):
        return self._gateway

    @property
    def guest_tls(self):
        return self._guest_tls

    def start(self):
        if self._directory is not None:
            raise RuntimeError("fixture already started")
        directory = tempfile.TemporaryDirectory(prefix="ryzova-phase7-mtls-")
        self._directory = directory
        try:
            srv_cert, srv_key = _cert(directory.name, "server")
            cli_cert, cli_key = _cert(directory.name, "client")
            client_pin = _pin(cli_cert)
            policy = (self.research_policy_factory(client_pin)
                      if self.research_policy_factory is not None else None)
            self._peer = SecureReadOnly9PPeer(
                {"probe": self.payload},
                server_context(str(srv_cert), str(srv_key), str(cli_cert)),
                client_pin, research_policy=policy)
            self._gateway = Local9PTLSGateway(
                client_context(str(cli_cert), str(cli_key), str(srv_cert)),
                _pin(srv_cert), self._peer.server_address[1], self.gateway_port)
            self.guest_cert_sha256 = _pin(srv_cert)
            self._guest_tls = NativeGuestTLS12Endpoint(
                str(srv_cert), str(srv_key),
                self._gateway.server_address[1], port=self.guest_tls_port,
                max_sessions=self.max_guest_sessions,
                max_frames_per_session=self.max_guest_frames)
            for listener in (self._peer, self._gateway, self._guest_tls):
                t = threading.Thread(target=listener.serve_forever,
                                     daemon=True, name="phase7-mtls-loopback")
                t.start()
                self._started_listeners.append(listener)
                self._threads.append(t)
        except Exception:
            self.close()
            raise
        return self

    def close(self):
        for listener in (self._guest_tls, self._gateway, self._peer):
            if listener is not None:
                # shutdown() deadlocks when serve_forever() never started.
                # Constructor errors can leave an unstarted peer/gateway.
                if listener in self._started_listeners:
                    listener.shutdown()
                listener.server_close()
        for t in self._threads:
            t.join(timeout=4)
            if t.is_alive():
                raise RuntimeError("TLS 9P fixture thread did not stop")
        self._gateway = self._peer = self._guest_tls = None
        self.guest_cert_sha256 = None
        self._threads.clear()
        self._started_listeners.clear()
        if self._directory is not None:
            self._directory.cleanup()
            self._directory = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()
