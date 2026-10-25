# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.2.1-8.2.4: opt-in, bounded real TLS/9P and pure-compute node PoC.

Two independent *processes/network namespaces* are tested in CI; NOT two
virtual machines or physical computers. The controller pins the TLS leaf DER,
requires verified TLS 1.3 with client certificates, and binds advertised
node identity to that live channel. Only public read-only 9P test files and
two pre-installed pure compute functions are exported; no arbitrary code.
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import socketserver
import ssl
import struct
import time

from ryzova.remote.native9p import Native9PConnection
from ryzova.remote.p9 import NinePError, ReadOnly9PClient, unframe
from ryzova.remote.phase8_cluster import NodeOffer, ResourceDenied, Workload

MAX_ENVELOPE = 16384
MAX_DATA = 4096
MAX_REQUESTS_PER_SESSION = 64
ALLOWED_9P = frozenset((100, 104, 108, 110, 112, 116, 120, 124))


class TransportDenied(Exception):
    """Network or untrusted node data rejected without sensitive details."""


def _exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise TransportDenied("remote service unavailable")
        data.extend(part)
    return bytes(data)


def send_message(sock, obj):
    if type(obj) is not dict:
        raise TransportDenied("invalid frame")
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not 2 <= len(raw) <= MAX_ENVELOPE:
        raise TransportDenied("message quota exceeded")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_message(sock):
    size = struct.unpack("!I", _exact(sock, 4))[0]
    if not 2 <= size <= MAX_ENVELOPE:
        raise TransportDenied("message quota exceeded")
    try:
        obj = json.loads(_exact(sock, size))
    except (UnicodeError, ValueError) as exc:
        raise TransportDenied("invalid message") from exc
    if type(obj) is not dict:
        raise TransportDenied("invalid message")
    return obj


def digest_file(cert_path):
    with open(cert_path, encoding="utf-8") as source:
        pem = source.read()
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def server_context(cert_path, key_path, client_cert_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(cert_path, key_path)
    context.load_verify_locations(cafile=client_cert_path)
    return context


def client_context(cert_path, key_path, server_cert_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain(cert_path, key_path)
    context.load_verify_locations(cafile=server_cert_path)
    return context


class _NodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        node = self.server
        self.request.settimeout(4)
        try:
            with node.context.wrap_socket(self.request, server_side=True) as tls:
                if tls.version() != "TLSv1.3":
                    raise TransportDenied("TLS1.3 required")
                der = tls.getpeercert(binary_form=True)
                if (type(der) is not bytes or
                        not hmac.compare_digest(hashlib.sha256(der).hexdigest(),
                                                node.controller_pin)):
                    raise TransportDenied("controller identity denied")
                # Created afresh for *each TLS session*; no cross-peer FIDs.
                connection = Native9PConnection({"probe": node.payload})
                # A credentialed peer still receives a strict per-session
                # request quota; do not permit unbounded read/compute loops.
                for _ in range(MAX_REQUESTS_PER_SESSION):
                    msg = recv_message(tls)
                    op = msg.get("op")
                    if op == "discover" and set(msg) == {"op"}:
                        send_message(tls, {"offer": node.offer_dict()})
                    elif op == "compute" and set(msg) == {"op", "kind", "data"}:
                        data = base64.b64decode(msg["data"], validate=True)
                        if not 0 < len(data) <= MAX_DATA:
                            raise TransportDenied("compute payload quota")
                        if msg["kind"] == "sha256":
                            result = hashlib.sha256(data).hexdigest()
                        elif msg["kind"] == "byte_count":
                            result = len(data)
                        else:
                            raise TransportDenied("operation denied")
                        send_message(tls, {"result": result})
                    elif op == "9p" and set(msg) == {"op", "frame"}:
                        raw = base64.b64decode(msg["frame"], validate=True)
                        kind, _, _ = unframe(raw)
                        if kind not in ALLOWED_9P:
                            raise TransportDenied("9P operation denied")
                        response = connection.process(raw)
                        send_message(tls, {"frame": base64.b64encode(response).decode("ascii")})
                    else:
                        raise TransportDenied("operation denied")
        except (TransportDenied, EOFError, OSError, ssl.SSLError,
                NinePError, ValueError, TypeError, KeyError, struct.error):
            # Never downgrade to plaintext or replay an unverified request.
            pass


class NodeService(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, *, context, controller_pin, node_id, node_pin,
                 payload=b"public 9p fixture", generation=1, slots=2):
        try:
            bind_ip = ipaddress.ip_address(address[0])
        except (TypeError, ValueError, IndexError):
            raise ValueError("literal private/loopback bind required") from None
        if bind_ip.is_unspecified or not (bind_ip.is_private or bind_ip.is_loopback):
            raise ValueError("public node listeners prohibited")
        if (type(payload) is not bytes or not 0 < len(payload) <= MAX_DATA
                or not isinstance(context, ssl.SSLContext)
                or context.verify_mode != ssl.CERT_REQUIRED
                or context.minimum_version != ssl.TLSVersion.TLSv1_3
                or context.maximum_version != ssl.TLSVersion.TLSv1_3
                or type(controller_pin) is not str or len(controller_pin) != 64
                or type(node_pin) is not str or len(node_pin) != 64):
            raise ValueError("invalid TLS node configuration")
        self.offer = NodeOffer(node_id, node_pin, frozenset({"compute", "storage"}),
                               frozenset({"amd64", "arm64"}), slots, 0, 5,
                               int(time.time()) + 3600,
                               generation=generation)
        self.controller_pin = controller_pin
        self.payload = payload
        self.context = context
        super().__init__(address, _NodeHandler)

    def offer_dict(self):
        offer = self.offer
        return dict(node_id=offer.node_id, cert_pin=offer.cert_pin,
                    roles=sorted(offer.roles),
                    architectures=sorted(offer.architectures),
                    slots=offer.slots, busy=offer.busy,
                    latency_ms=offer.latency_ms,
                    lease_until=offer.lease_until,
                    generation=offer.generation, local=False,
                    max_payload=offer.max_payload)


class RemoteNode:
    """Client context configured by the trusted controller, not node input."""

    def __init__(self, node_id, address, tls_name, expected_pin, context):
        if (type(node_id) is not str or type(tls_name) is not str or
                type(expected_pin) is not str or len(expected_pin) != 64 or
                not isinstance(context, ssl.SSLContext)
                or context.verify_mode != ssl.CERT_REQUIRED
                or context.check_hostname is not True
                or context.minimum_version != ssl.TLSVersion.TLSv1_3
                or context.maximum_version != ssl.TLSVersion.TLSv1_3):
            raise ValueError("invalid node endpoint")
        self.node_id, self.address = node_id, address
        self.tls_name, self.expected_pin, self.context = tls_name, expected_pin, context

    def connect(self):
        raw = socket.create_connection(self.address, timeout=4)
        raw.settimeout(4)
        try:
            secure = self.context.wrap_socket(raw, server_hostname=self.tls_name)
            der = secure.getpeercert(binary_form=True)
            if (secure.version() != "TLSv1.3" or
                    not der or not hmac.compare_digest(
                        hashlib.sha256(der).hexdigest(), self.expected_pin)):
                secure.close()
                raise TransportDenied("node identity mismatch")
            return secure
        except Exception:
            raw.close()
            raise

    def discover(self, registry, *, now):
        if not registry.enabled or self.node_id not in registry._pins:
            raise ResourceDenied("node admission denied")
        with self.connect() as tls:
            # Identity comes from this verified TLS socket, NOT JSON fields.
            bound_pin = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            send_message(tls, {"op": "discover"})
            raw = recv_message(tls)
        if set(raw) != {"offer"} or type(raw["offer"]) is not dict:
            raise TransportDenied("invalid node announcement")
        offer = raw["offer"]
        if offer.get("node_id") != self.node_id or offer.get("cert_pin") != bound_pin:
            raise TransportDenied("announcement identity mismatch")
        try:
            model = NodeOffer(
                node_id=offer["node_id"], cert_pin=offer["cert_pin"],
                roles=frozenset(offer["roles"]),
                architectures=frozenset(offer["architectures"]),
                slots=offer["slots"], busy=offer["busy"],
                latency_ms=offer["latency_ms"],
                lease_until=offer["lease_until"],
                generation=offer["generation"], local=offer["local"],
                max_payload=offer["max_payload"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TransportDenied("invalid resource announcement") from exc
        if model.local:
            raise TransportDenied("remote cannot advertise as local")
        registry.admit(model, presented_fingerprint=bound_pin, now=now)
        return model

    def compute(self, kind, payload):
        task = Workload(kind=kind, payload=payload, allow_remote=True)
        with self.connect() as tls:
            send_message(tls, {"op": "compute", "kind":task.kind,
                               "data":base64.b64encode(task.payload).decode("ascii")})
            response = recv_message(tls)
        if set(response) != {"result"}:
            raise TransportDenied("invalid compute response")
        value = response["result"]
        # Verify pure output independently, including malicious result rejection.
        expected = (hashlib.sha256(payload).hexdigest() if kind == "sha256"
                    else len(payload))
        if type(value) is not type(expected) or value != expected:
            raise TransportDenied("remote result integrity failed")
        return value

    def read_probe(self):
        with self.connect() as tls:
            def exchange(packet):
                send_message(tls, {"op": "9p",
                                   "frame": base64.b64encode(packet).decode("ascii")})
                obj = recv_message(tls)
                if set(obj) != {"frame"} or type(obj["frame"]) is not str:
                    raise TransportDenied("invalid 9P reply")
                return base64.b64decode(obj["frame"], validate=True)
            return ReadOnly9PClient(exchange).read_file("probe", max_total=4096)


def run_node_from_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--controller-cert", required=True)
    parser.add_argument("--payload", default="public distributed 9P file")
    args = parser.parse_args()
    with NodeService(
            (args.ip, args.port),
            context=server_context(args.cert, args.key, args.controller_cert),
            controller_pin=digest_file(args.controller_cert),
            node_id=args.node_id, node_pin=digest_file(args.cert),
            payload=args.payload.encode("ascii")) as service:
        service.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    run_node_from_args()
