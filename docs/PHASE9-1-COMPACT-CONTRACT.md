# Phase 9.1 — Compact Environment Contract v1 (research)

Status: **contract-only prototype**. No Linux, Windows or macOS executable compatibility is implemented or claimed.

## Boundary and baseline
Branch from Phase 8.2 merged main commit `0a09a9833c895172e359a1d89216fc0a81e4eaf2`.
Preserve native 9front/AMD64 build, driver, mTLS, 9P, resource-coordinator and two-netns regression gates. This change does not alter native kernel, 9front upstream, or drivers.

## Identifier and version
An environment identifier has form `compact/<lowercase-slug>`, e.g. `compact/linux`, `compact/windows`, `compact/mac`. These are **names**, not implemented emulators.
API uses independent major/minor integers. Major mismatch fails closed. Minor versions may negotiate only supported minor versions; no implicit future feature support.

## API v1 negotiation
Request is an exact object containing `environment`, `api_major`, `api_minor`, `capabilities`. Known *declarative* capability names: `namespace.read`, `process.spawn`, `resource.query`, `ipc.9p`.
Response echoes the validated environment and negotiated version, sorts the declared capabilities, and explicitly reports `abi: none`, `status: contract-only`.
Capabilities are **not grants**, permissions, or implemented operations. A future runtime must independently authorize each action and enforce quotas and isolation.

## ABI boundary (not yet implemented)
Future ABI v1 requires an independently reviewed binary wire layout, endian/width/alignment rules, calling convention, handle lifetime, error namespace, syscall translation and guest/host trust boundary. This Python validator is **not** a binary ABI, POSIX/Win32/Darwin implementation, compatibility promise, or security sandbox.

## Acceptance
Run `python3 -m unittest discover -s tests -p 'test_compact_contract_v1.py' -v` plus all required existing PR CI.
Fail closed on malformed identifiers, unsupported versions, unknown/duplicate capabilities and extra fields.
Do not merge without exact-head required CI and native source-built QEMU/security/driver regression evidence.
