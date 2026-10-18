# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.5: real TLS 1.3 mutual-certificate localhost request/reply PoC.

A developer test server binds ONLY 127.0.0.1. Certs and keys are injected,
never embedded. Not connected to the Ryzova kernel or an external host.
"""
import hashlib
import json
import socket
import ssl
import struct
import threading

from ryzova.remote.trust import RemoteDenied

MAX_ENVELOPE = 18000
ALLOWED_OPS = frozenset(("9p", "compute", "page"))

class TLSUnavailable(Exception):
    pass


def _exact(sock, length):
    data = bytearray()
    while len(data) < length:
        piece = sock.recv(length-len(data))
        if not piece:
            raise TLSUnavailable("connection closed before a complete message")
        data.extend(piece)
    return bytes(data)


def _receive(sock):
    size = struct.unpack("!I", _exact(sock, 4))[0]
    if not 0 < size <= MAX_ENVELOPE:
        raise TLSUnavailable("packet length limit")
    return _exact(sock, size)


def _send(sock, body):
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_ENVELOPE:
        raise TLSUnavailable("invalid bounded packet")
    sock.sendall(struct.pack("!I", len(body))+body)


def _pin(cert):
    if not isinstance(cert, bytes) or not cert:
        raise TLSUnavailable("missing authenticated TLS peer")
    return hashlib.sha256(cert).hexdigest()


def server_context(certfile, keyfile, trusted_client_cert):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=certfile,keyfile=keyfile)
    ctx.load_verify_locations(cafile=trusted_client_cert)
    return ctx


def client_context(certfile, keyfile, trusted_server_cert):
    ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=trusted_server_cert)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.check_hostname=True
    ctx.load_cert_chain(certfile=certfile,keyfile=keyfile)
    return ctx


class TLSLoopbackServer:
    def __init__(self, context, endpoint, handlers, expected_client_pin, *, timeout=1.5):
        if not isinstance(context,ssl.SSLContext) or not 0.1<=timeout<=10:
            raise ValueError("invalid TLS policy")
        if not isinstance(expected_client_pin,str) or len(expected_client_pin)!=64:
            raise ValueError("expected client SHA256 fingerprint required")
        if not handlers or not set(handlers).issubset(ALLOWED_OPS):
            raise ValueError("only approved services")
        self.context=context
        self.endpoint=endpoint
        self.handlers=dict(handlers)
        self.client_pin=expected_client_pin
        self.timeout=timeout
        self._halt=threading.Event()
        self._socket=None
        self._thread=None
        self.port=None
        self.denied=0
        self.handled=0

    def start(self):
        if self._thread is not None:
            raise RuntimeError("server already started")
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(("127.0.0.1",0))
        listener.listen(8)
        listener.settimeout(.1)
        self._socket=listener
        self.port=listener.getsockname()[1]
        self._thread=threading.Thread(target=self._serve,daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while not self._halt.is_set():
            try:
                conn,_=self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with conn:
                    conn.settimeout(self.timeout)
                    with self.context.wrap_socket(conn,server_side=True) as secure:
                        if secure.version()!="TLSv1.3" or _pin(secure.getpeercert(binary_form=True))!=self.client_pin:
                            raise TLSUnavailable("client identity not pinned")
                        packet=_receive(secure)
                        # Untrusted 'op' is used only to select a predeclared allowlist,
                        # never to execute arbitrary code or access a filesystem.
                        outer=json.loads(packet)
                        op=outer["message"]["op"]
                        if not isinstance(op,str) or op not in self.handlers:
                            raise RemoteDenied("operation denied")
                        accepted=self.endpoint.verify(packet,"request",op)
                        reply=self.handlers[op](accepted)
                        if not isinstance(reply,bytes) or len(reply)>8192:
                            raise TLSUnavailable("oversized service result")
                        _send(secure,self.endpoint.sign(outer["message"]["sender"],
                                                        "response",op,reply))
                        self.handled+=1
            except (ValueError,TypeError,KeyError,UnicodeError,OSError,ssl.SSLError,
                    RemoteDenied,TLSUnavailable):
                self.denied+=1

    def stop(self):
        self._halt.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise RuntimeError("loopback test server did not stop")
        self._thread=None

    def __enter__(self):
        return self.start()

    def __exit__(self,*_):
        self.stop()


class TLSLoopbackClient:
    def __init__(self, context, endpoint, expected_server_pin, port, *, timeout=1.5):
        if not isinstance(context,ssl.SSLContext) or not isinstance(port,int) or not 0<port<65536:
            raise ValueError("invalid TLS client")
        if not isinstance(expected_server_pin,str) or len(expected_server_pin)!=64:
            raise ValueError("server pin required")
        if not 0.1<=timeout<=10:
            raise ValueError("timeout policy")
        self.context=context
        self.endpoint=endpoint
        self.server_pin=expected_server_pin
        self.port=port
        self.timeout=timeout

    def request(self, op, payload):
        if op not in ALLOWED_OPS:
            raise TLSUnavailable("operation not allowed")
        wire=self.endpoint.sign("server","request",op,payload)
        try:
            with socket.create_connection(("127.0.0.1",self.port),timeout=self.timeout) as raw:
                raw.settimeout(self.timeout)
                with self.context.wrap_socket(raw,server_hostname="localhost") as secure:
                    if secure.version()!="TLSv1.3" or _pin(secure.getpeercert(binary_form=True))!=self.server_pin:
                        raise TLSUnavailable("server identity not pinned")
                    _send(secure,wire)
                    packet=_receive(secure)
            return self.endpoint.verify(packet,"response",op)
        except (OSError, ssl.SSLError, RemoteDenied, ValueError, TLSUnavailable) as exc:
            raise TLSUnavailable("encrypted service unavailable or unauthenticated") from exc
