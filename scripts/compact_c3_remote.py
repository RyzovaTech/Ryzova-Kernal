# SPDX-License-Identifier: GPL-3.0-only
"""C3 QEMU file routes through two network-isolated 9P peers."""
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ryzova.remote.native_bridge import Local9PTLSGateway, SecureReadOnly9PPeer
from ryzova.remote.native_guest_tls import NativeGuestTLS12Endpoint
from ryzova.remote.phase7_fixture import _cert, _pin
from ryzova.remote.tlsloop import client_context, server_context

MOUNT = "/n/compactc3"
FILENAME = "probe"
RESOURCE = f"{MOUNT}/{FILENAME}"
SECONDARY_MOUNT = "/n/compactc3b"
SECONDARY_RESOURCE = f"{SECONDARY_MOUNT}/{FILENAME}"
TIMEOUT = 25


def payload(commit, node="a"):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or node not in ("a", "b"):
        raise ValueError("exact source commit and C3 node required")
    return (json.dumps(dict(items=[2, 3, 5], source=commit, node=node), separators=(",", ":")) + "\n").encode()


def ip(*args):
    subprocess.run(["sudo", "-n", "ip", *args], check=True, capture_output=True, timeout=10)


def delete(*args):
    subprocess.run(["sudo", "-n", "ip", *args], capture_output=True, timeout=10)


def listener(stack, server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    stack.callback(server.server_close)
    thread.start()
    stack.callback(server.shutdown)
    return server


def peer_main(commit, node, address, server_cert, server_key, client_cert):
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    with ExitStack() as stack:
        server = listener(stack, SecureReadOnly9PPeer(
            {FILENAME: payload(commit, node)},
            server_context(server_cert, server_key, client_cert), _pin(Path(client_cert)),
            listen_host=address, io_timeout=TIMEOUT))
        print(json.dumps(dict(pid=os.getpid(), netns=os.readlink("/proc/self/ns/net"),
                              port=server.server_address[1])), flush=True)
        stop.wait()


class PartitionHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = self.server.route
        if self.path != route.partition_path or route.partitioned:
            self.send_error(404)
            return
        try:
            ip("link", "set", route.links["a"], "down")
        except subprocess.SubprocessError:
            self.send_error(500)
            return
        route.partitioned = True
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"C3_PRIMARY_LINK_DOWN\n")


class Route:
    def __init__(self, commit):
        self.commit = commit
        self.stack = ExitStack()
        self.links = {}
        self.peers = {}
        self.gateways = {}
        self.endpoints = {}
        self.pins = {}
        self.partition_path = "/partition-" + secrets.token_hex(12)
        self.partitioned = False

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.stack.close()

    def start(self):
        with ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="compact-c3-"))
            cli_cert, cli_key = _cert(directory, "client")
            suffix = secrets.token_hex(3)
            for i, node in enumerate(("a", "b")):
                namespace = f"rz3{node}-{suffix}"
                host, peer = f"rz3h{node}{suffix}", f"rz3p{node}{suffix}"
                host_addr, node_addr = f"10.235.{96+i}.1", f"10.235.{96+i}.2"
                ip("netns", "add", namespace)
                stack.callback(delete, "netns", "del", namespace)
                ip("link", "add", host, "type", "veth", "peer", "name", peer)
                stack.callback(delete, "link", "del", host)
                ip("link", "set", peer, "netns", namespace)
                ip("addr", "add", f"{host_addr}/30", "dev", host)
                ip("link", "set", host, "up")
                ip("-n", namespace, "addr", "add", f"{node_addr}/30", "dev", peer)
                ip("-n", namespace, "link", "set", "lo", "up")
                ip("-n", namespace, "link", "set", peer, "up")
                self.links[node] = host
                node_directory = Path(directory) / node
                node_directory.mkdir()
                srv_cert, srv_key = _cert(node_directory, "server")
                process = subprocess.Popen(
                    ["sudo", "-n", "ip", "netns", "exec", namespace, sys.executable,
                     str(Path(__file__).resolve()), "--peer", self.commit, node, node_addr,
                     str(srv_cert), str(srv_key), str(cli_cert)],
                    stdout=subprocess.PIPE, text=True)
                stack.callback(self.stop_peer, process, namespace)
                ready, _, _ = select.select([process.stdout], [], [], 10)
                if not ready:
                    raise ValueError(f"C3 peer {node} never became ready")
                identity = json.loads(process.stdout.readline())
                self.peers[node] = dict(identity, address=node_addr)
                pin = _pin(srv_cert)
                self.pins[node] = pin
                gateway = listener(stack, Local9PTLSGateway(
                    client_context(str(cli_cert), str(cli_key), str(srv_cert)), pin,
                    identity["port"], port=0, upstream_host=node_addr, io_timeout=TIMEOUT))
                self.gateways[node] = gateway
                self.endpoints[node] = listener(stack, NativeGuestTLS12Endpoint(
                    str(srv_cert), str(srv_key), gateway.server_address[1], port=0, io_timeout=TIMEOUT))
            namespaces = {identity["netns"] for identity in self.peers.values()}
            if len(namespaces) != 2 or os.readlink("/proc/self/ns/net") in namespaces:
                raise ValueError("C3 peers do not occupy independent network namespaces")
            control = ThreadingHTTPServer(("127.0.0.1", 0), PartitionHandler)
            control.route = self
            self.control = listener(stack, control)
            self.stack = stack.pop_all()
        return self

    @staticmethod
    def stop_peer(process, namespace):
        if process.poll() is None:
            pids = subprocess.check_output(["sudo", "-n", "ip", "netns", "pids", namespace],
                                           text=True, timeout=10).split()
            if pids:
                subprocess.run(["sudo", "-n", "kill", "-TERM", *pids], check=False, timeout=10)
            process.wait(timeout=8)
        process.stdout.close()


def route_fixture(commit):
    return Route(commit)


def mount_commands(route, node="a"):
    port = route.endpoints[node].server_address[1]
    root = MOUNT if node == "a" else SECONDARY_MOUNT
    service = f"compactc3{node}"
    pin = f"/tmp/{service}-pin"
    return [
        f"echo 'x509 sha256={route.pins[node]}' >{pin}",
        f"mkdir -p {root}",
        f"srv -enq 'tlsclient -n localhost -t {pin} tcp!10.0.2.2!{port}' {service}",
        f"mount -n /srv/{service} {root}",
    ]


def recovery_commands(route):
    port = route.control.server_address[1]
    return [
        "echo C3_PARTITION_BEGIN",
        f"hget http://10.0.2.2:{port}{route.partition_path}",
        f"if(cat {RESOURCE} >/tmp/c3-dead.out >[2]/tmp/c3-dead.err) echo C3_UNEXPECTED_READ; if not echo C3_PRIMARY_READ_FAILED",
        "sha1sum -2 256 /tmp/c3-dead.out; cat /tmp/c3-dead.err; echo C3_PARTITION_END",
    ] + mount_commands(route, "b")


def transport_evidence(route, commit, serial):
    section = re.search(rb"(?ms)^C3_PARTITION_BEGIN\r?\n(.*?)^C3_PARTITION_END\r?$", serial)
    body = section[1] if section else b""
    if (not route.partitioned or not line(body, "C3_PRIMARY_LINK_DOWN") or
            line(body, "C3_UNEXPECTED_READ") or not line(body, "C3_PRIMARY_READ_FAILED") or
            digests(body, "/tmp/c3-dead.out") != [sha(b"")] or
            not re.search(rb"(?m)^cat: [^\r\n]*" + re.escape(RESOURCE.encode()) +
                          rb"[^\r\n]*(?:mount rpc error|hungup|timed out|I/O|i/o|connection)", body)):
        raise ValueError("C3 did not demonstrate a failed primary read after link loss")
    routes = {}
    for node, identity in route.peers.items():
        endpoint, gateway = route.endpoints[node], route.gateways[node]
        if endpoint.tls12_sessions < 1 or gateway.verified_tls_sessions < 1 or gateway.forwarded_frames < 5:
            raise ValueError(f"C3 node {node} did not carry the pinned guest workload")
        routes[node] = dict(netns=identity["netns"], address=identity["address"],
                            guest_server_pin=route.pins[node], input_sha256=sha(payload(commit, node)),
                            guest_tls_sessions=endpoint.tls12_sessions,
                            verified_peer_sessions=gateway.verified_tls_sessions,
                            peer_9p_frames=gateway.forwarded_frames)
    return dict(schema="compact-c3-remote-file/v2", source_commit=commit,
                namespace_path=RESOURCE, recovery_path=SECONDARY_RESOURCE, nodes=routes,
                primary_link_failure=True, explicit_secondary_mount=True)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def line(serial, marker):
    return re.search(rb"(?m)^" + re.escape(marker.encode()) + rb"\r?$", serial) is not None


def digests(serial, path):
    return [match.decode() for match in re.findall(
        rb"(?m)^([0-9a-f]{64})[ \t]+" + re.escape(path.encode()) + rb"\r?$", serial)]


def linux_commands(node):
    path = "/home/share/probe"
    root = MOUNT if node == "a" else SECONDARY_MOUNT
    label = f"/tmp/c3-{node}"
    grant = "" if node == "denied" else f"-M 'r:/home/share={root}' "
    return [
        f"$c1 -r -b 16777216 {grant}/tmp/c1-jq -c . {path} >{label}.out >[2]{label}.log",
        f"grep -v '^COMPACT_(LINUX_RESULT|JOBS_STATS|RESOURCE_STATS) ' {label}.log >{label}.err",
        f"sha1sum -2 256 {label}.out {label}.err; grep '^COMPACT_LINUX_RESULT ' {label}.log",
    ]


def linux_result(serial, commit):
    denied = b"jq: error: Could not open file /home/share/probe: No such file or directory\n"
    cases = {}
    for node in ("a", "denied", "b"):
        code, out, err = (2, b"", denied) if node == "denied" else (0, payload(commit, node), b"")
        label = f"/tmp/c3-{node}"
        match = re.search(rb"(?ms)^C3_LINUX_" + node.encode() + rb"_BEGIN\r?\n(.*?)^C3_LINUX_" +
                          node.encode() + rb"_END\r?$", serial)
        body = match[1] if match else b""
        if (digests(body, label+".out") != [sha(out)] or digests(body, label+".err") != [sha(err)] or
                not re.search(rb"(?m)^COMPACT_LINUX_RESULT status=0 exited=1 exit=" + str(code).encode() +
                              rb" steps=[1-9]\d* syscalls=[1-9]\d*\r?$", body)):
            raise ValueError(f"Compact Linux remote jq result differs for {node}")
        cases[node] = dict(exit_code=code, stdout_hex=out.hex(), stderr_hex=err.hex())
    return cases


if __name__ == "__main__":
    if len(sys.argv) != 8 or sys.argv[1] != "--peer":
        raise SystemExit("expected C3 peer parameters")
    peer_main(*sys.argv[2:])
