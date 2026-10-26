# SPDX-License-Identifier: AGPL-3.0-only
"""Research native guest certificate possession proof; not production PKI."""
import hashlib
import re

from phase6_native_9p import payload_for_commit


def commands():
    # Ephemeral credentials travel only across the disposable QEMU slirp
    # harness. Never print their contents or upload them as CI artifacts.
    return (
        "hget http://10.0.2.2:8000/guest-identity-cert.pem > /tmp/ryzova8-cert.pem; "
        "echo RYZOVA_RUNTIME_STAGE_20",
        "hget http://10.0.2.2:8000/guest-identity-key.pem > /tmp/ryzova8-key.pem; "
        "chmod 600 /tmp/ryzova8-key.pem; echo RYZOVA_RUNTIME_STAGE_21",
        "auth/factotum -n; auth/pemdecode 'PRIVATE KEY' /tmp/ryzova8-key.pem | "
        "auth/asn12rsa -t 'service=tls' > /mnt/factotum/ctl; "
        "rm -f /tmp/ryzova8-key.pem; echo RYZOVA_RUNTIME_STAGE_22",
        "mkdir -p /n/ryzova8; srv -enq 'tlsclient -n localhost "
        "-c /tmp/ryzova8-cert.pem -t /tmp/ryzova7-trusted tcp!10.0.2.2!15642' ryzova8; "
        "mount -n /srv/ryzova8 /n/ryzova8; echo RYZOVA_RUNTIME_STAGE_23",
        "echo RYZOVA_GUEST_IDENTITY_READ_BEGIN; cat /n/ryzova8/probe; "
        "echo RYZOVA_GUEST_IDENTITY_READ_END; echo RYZOVA_RUNTIME_STAGE_24",
        "sha1sum -2 256 /n/ryzova8/probe; echo RYZOVA_RUNTIME_STAGE_25; "
        "echo RYZOVA_GUEST_IDENTITY_DONE",
    )


def inspect(serial, commit, guest_pin, authenticated_sessions, frames):
    payload = payload_for_commit(commit).rstrip(b"\n")
    digest = hashlib.sha256(payload_for_commit(commit)).hexdigest().encode()
    section = re.search(
        rb"(?:^|\r?\n)RYZOVA_GUEST_IDENTITY_READ_BEGIN\r?\n(.*?)"
        rb"(?:\r?\n)RYZOVA_GUEST_IDENTITY_READ_END(?:\r?\n|$)", serial, re.S)
    line = lambda value: re.search(
        rb"(?:^|\r?\n)" + re.escape(value) + rb"(?:\r?\n|$)", serial) is not None
    checks = {
        "native_guest_read": section is not None and re.search(
            rb"(?:^|\r?\n)" + re.escape(payload) + rb"(?:\r?\n|$)",
            section.group(1)) is not None,
        "guest_digest": re.search(rb"(?:^|\r?\n)" + re.escape(digest)
            + rb"\s+/n/ryzova8/probe(?:\r?\n|$)", serial) is not None,
        "runtime_stages": all(line(f"RYZOVA_RUNTIME_STAGE_{i}".encode())
                              for i in range(20, 26)) and line(b"RYZOVA_GUEST_IDENTITY_DONE"),
        "live_mtls_guest_identity": type(authenticated_sessions) is int
            and authenticated_sessions >= 1,
        "authenticated_9p_frames": type(frames) is int and frames >= 5,
        "pinned_guest_leaf": type(guest_pin) is str
            and re.fullmatch(r"[a-f0-9]{64}", guest_pin) is not None,
        "no_kernel_panic": re.search(rb"(?im)(?:^|\n)panic:", serial) is None,
    }
    return {
        "schema": "ryzova-native-guest-mtls-identity/v1",
        "source_commit": commit, "checks": checks, "passed": all(checks.values()),
        "guest_identity": "ryzova-qemu-guest", "guest_leaf_sha256": guest_pin,
        "authenticated_guest_sessions": authenticated_sessions,
        "authenticated_9p_frames": frames,
        "guest_identity_forwarded_to_remote_peer": False,
        "per_human_user_acl_verified": False,
        "production_credential_provisioning_verified": False,
        "physical_hardware_certified": False, "release_permitted": False,
    }
