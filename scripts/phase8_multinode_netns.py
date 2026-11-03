#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Actual 2 isolated Linux network namespaces + host controller CI fixture.

Not separate QEMU guests or physical hosts. Requires root and iproute2 on an
isolated disposable Linux CI runner; namespaces and keys are always cleaned.
"""
from pathlib import Path
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

from ryzova.remote.phase8_cluster import (
    ResourceRegistry, UnifiedCoordinator, Workload, ResourceDenied)
from ryzova.remote.phase8_multinode import (
    RemoteNode, client_context, digest_file, TransportDenied)

ROOT = Path(__file__).resolve().parent.parent
NS = ("rz82nodea", "rz82nodeb")
HOST_LINK = ("rz82hosta", "rz82hostb")
NODE_LINK = ("rz82peera", "rz82peerb")
HOST_ADDR = ("10.233.180.1", "10.233.181.1")
NODE_ADDR = ("10.233.180.2", "10.233.181.2")
PORTS = (17341, 17342)


def cmd(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=25)


def cert(root, name):
    pem, key = root / (name + ".pem"), root / (name + ".key")
    cmd("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-sha256", "-days", "1", "-subj", "/CN=" + name,
        "-addext", "subjectAltName=DNS:" + name,
        "-keyout", str(key), "-out", str(pem))
    return str(pem), str(key)


def setup_ns(index):
    name, host, node = NS[index], HOST_LINK[index], NODE_LINK[index]
    cmd("ip", "netns", "add", name)
    cmd("ip", "link", "add", host, "type", "veth", "peer", "name", node)
    cmd("ip", "link", "set", node, "netns", name)
    cmd("ip", "addr", "add", HOST_ADDR[index] + "/30", "dev", host)
    cmd("ip", "link", "set", host, "up")
    cmd("ip", "-n", name, "addr", "add", NODE_ADDR[index] + "/30", "dev", node)
    cmd("ip", "-n", name, "link", "set", "lo", "up")
    cmd("ip", "-n", name, "link", "set", node, "up")


def connect_until_ready(client, process):
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError("isolated node process exited early")
        try:
            with client.connect():
                return
        except (OSError, TransportDenied):
            time.sleep(0.1)
    raise RuntimeError("isolated TLS node never became ready")


def main():
    if os.geteuid() != 0:
        raise SystemExit("phase8 namespace evidence requires root, never silently skip")
    old_umask = os.umask(0o077)
    processes = []
    created = []
    try:
        with tempfile.TemporaryDirectory(prefix="ryzova-8-2-netns-") as directory:
            root = Path(directory)
            controller_cert, controller_key = cert(root, "controller")
            files = [cert(root, "node-a"), cert(root, "node-b")]
            for i in range(2):
                setup_ns(i)
                created.append(NS[i])
            endpoints = {}
            for i, name in enumerate(("node-a", "node-b")):
                pem, key = files[i]
                env = dict(os.environ)
                env["PYTHONPATH"] = str(ROOT)
                args = [
                    "ip", "netns", "exec", NS[i], sys.executable,
                    "-m", "ryzova.remote.phase8_multinode",
                    "--ip", NODE_ADDR[i], "--port", str(PORTS[i]),
                    "--node-id", name, "--cert", pem, "--key", key,
                    "--controller-cert", controller_cert,
                    "--payload", "public fixture " + name,
                ]
                proc = subprocess.Popen(args, cwd=ROOT, env=env,
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
                processes.append(proc)
                endpoints[name] = RemoteNode(
                    name, (NODE_ADDR[i], PORTS[i]), name, digest_file(pem),
                    client_context(controller_cert, controller_key, pem))
                connect_until_ready(endpoints[name], proc)
            registry = ResourceRegistry({
                name: node.expected_pin for name, node in endpoints.items()},
                enabled=True)
            now = int(time.time())
            for name, remote in endpoints.items():
                registered = remote.discover(registry, now=now)
                assert registered.node_id == name
                response = remote.read_probe()
                assert response == ("public fixture " + name).encode()
                assert hashlib.sha256(response).hexdigest() == remote.compute("sha256", response)
            worker = UnifiedCoordinator(
                registry, {name: remote.compute for name, remote in endpoints.items()},
                enabled=True)
            task = Workload("sha256", b"network-separated-public",
                            architecture="amd64", allow_remote=True)
            nodes = [worker.submit(task, now=now).node_id for _ in range(4)]
            assert nodes == ["node-a", "node-b", "node-a", "node-b"], nodes
            # Simulate partition from the host: both server processes remain
            # alive, but node-a is unreachable across the isolated veth.
            cmd("ip", "link", "set", HOST_LINK[0], "down")
            fallback = UnifiedCoordinator(
                registry, {name: remote.compute for name, remote in endpoints.items()},
                enabled=True).submit(
                    Workload("byte_count", b"fallback", allow_remote=True),
                    now=now)
            assert (fallback.node_id, fallback.result, fallback.attempts) == (
                "node-b", 8, 2), fallback
            assert processes[0].poll() is None
            # Explicit re-provisioning after partition; no silent unquarantine
            # of a failed node or bypass of identity pin checks.
            cmd("ip", "link", "set", HOST_LINK[0], "up")
            fresh = ResourceRegistry(
                {name: node.expected_pin for name, node in endpoints.items()},
                enabled=True)
            assert endpoints["node-a"].discover(fresh, now=int(time.time())).node_id == "node-a"
            assert endpoints["node-a"].read_probe() == b"public fixture node-a"
            print(json.dumps({
                "status":"PASS", "isolation":"two Linux network namespaces",
                "mTLS":"TLSv1.3 mutual auth with DER leaf pin",
                "9p":"two independent authenticated remote file reads",
                "automatic_placements":nodes,
                "partition_fallback":fallback.node_id,
                "recovered":"node-a after explicit fresh authorization",
                "guest_native_identity":False,
                "remote_cpu_cores_added":False,
            }, sort_keys=True))
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        for name in reversed(created):
            subprocess.run(("ip", "netns", "del", name), check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in HOST_LINK:
            subprocess.run(("ip", "link", "del", name), check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.umask(old_umask)


if __name__ == "__main__":
    main()
