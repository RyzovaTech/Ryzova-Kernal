#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed native Ryzova QEMU guest -> TCP 9P2000 test evidence parser."""
import hashlib
import re

PREFIX = "RYZOVA_PHASE6_NATIVE_9P_"
PORT = 15640

def payload_for_commit(commit):
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("exact 40-character source commit required")
    return (PREFIX + commit + "\n").encode("ascii")

def guest_commands():
    return (
        ("phase6-native-tcp-9p-mount",
         "mkdir -p /n/ryzova6; "
         "srv -nq tcp!10.0.2.2!15640 ryzova6; "
         "mount -n /srv/ryzova6 /n/ryzova6; "
         "echo RYZOVA_PHASE6_READ_BEGIN; "
         "cat /n/ryzova6/probe; "
         "echo RYZOVA_PHASE6_READ_END; echo RYZOVA_RUNTIME_STAGE_14"),
        ("phase6-native-tcp-9p-digest",
         "sha1sum -2 256 /n/ryzova6/probe; "
         "echo RYZOVA_RUNTIME_STAGE_15; echo RYZOVA_PHASE6_NATIVE_DONE"),
    )

def _line(data, value):
    return bool(re.search(rb"(?:^|\r?\n)" + re.escape(value) + rb"(?:\r?\n|$)", data))

def inspect_native_9p_serial(serial, source_commit, served_requests=0):
    payload = payload_for_commit(source_commit)
    expected = hashlib.sha256(payload).hexdigest().encode("ascii")
    section = re.search(
        rb"(?:^|\r?\n)RYZOVA_PHASE6_READ_BEGIN\r?\n(.*?)"
        rb"(?:\r?\n)RYZOVA_PHASE6_READ_END(?:\r?\n|$)",
        serial, re.S,
    )
    text = section.group(1) if section else b""
    checks = {
        "native_guest_file_contains_expected_commit_challenge":
            _line(text, payload.rstrip(b"\n")),
        "guest_sha256_of_native_tcp_9p_file":
            bool(re.search(rb"(?:^|\r?\n)" + re.escape(expected)
                           + rb"\s+/n/ryzova6/probe(?:\r?\n|$)", serial)),
        "two_stages_completed":
            _line(serial,b"RYZOVA_RUNTIME_STAGE_14") and
            _line(serial,b"RYZOVA_RUNTIME_STAGE_15"),
        "native_9p_sequence_completed":
            _line(serial,b"RYZOVA_PHASE6_NATIVE_DONE"),
        "tcp_9p_server_exchanged_multiple_frames":served_requests >= 5,
        "no_observed_kernel_panic":
            re.search(rb"(?im)(?:^|\n)panic:",serial) is None
    }
    return {
        "schema":"ryzova-phase6-native-9p-qemu/v1",
        "passed":all(checks.values()),
        "checks":checks,
        "payload_sha256":expected.decode("ascii"),
        "source_commit":source_commit,
        "host_9p_frames":served_requests,
        "scope":"source-built Ryzova AMD64 kernel guest -> QEMU user-mode TCP -> "
                "unauthenticated read-only CI-host 9P2000 fixture",
        "NOT_verified":[
            "mutual TLS or production peer authentication inside Ryzova guest",
            "any external machine or Internet 9P mount",
            "remote physical RAM, kernel page faults or CPU offload",
            "remote write support or authenticated production filesystem",
            "physical hardware and long-duration stress"
        ]
    }
