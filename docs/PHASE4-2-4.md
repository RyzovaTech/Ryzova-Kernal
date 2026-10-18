# Phase 4.2–4.4 — Integration, Build Profile and Developer Kernel Contract

## Phase 4.2: driver compatibility regression integration
The D-series driver source inventory, evidence matrix, and release CI already exist and are maintained separately by the driver agent. This phase adds an integration-level presence and provenance gate and executes existing driver Python unit suites. It does not edit driver implementations, certify devices, or claim that static probes represent runtime support. Device-specific QEMU/physical qualification remains separately required.

## Phase 4.3: controlled build profile
The `ryzova/config/amd64-developer.json` profile describes the existing native 9front `mk` pipeline, the exact pinned 9front guest-image SHA256, and the source selection and kernel hash artifacts. The profile is explicitly NON-RELEASE. Identical toolchain inputs alone do not prove bit-for-bit reproducible binaries. Actual fresh native compilation and QEMU boot are already independently covered by `.github/workflows/phase3-native-build.yml`; do not treat the static integrity gate as a replacement.

## Phase 4.4: OS variant contract
The JSON SDK contract declares AMD64, experimental-0, read-only `#Z` kernel identity and inherited 9P / namespaces. This is a machine-readable informational contract, NOT an ABI freeze, SDK toolchain, Linux/Windows/macOS executable support, or a security guarantee. Downstream OS variants require their own compatible userspace, device licensing review and integration testing.

## Gates and limitations
`scripts/phase4_integrity.py` rejects absent integration workflows, reintroduced automatic 9front sync, inconsistent experimental ABI metadata, bad developer build configuration and compatibility overclaims. It emits a SHA256 inventory artifact. The corresponding CI also runs the existing driver parser unit tests without modifying driver sources.

Remaining work before production claims: full driver change-to-runtime regression mapping, strict branch protection, physical machine qualification, cross-host binary reproducibility checks, a versioned stable ABI with compatibility tests, license clearance and production release signing.
