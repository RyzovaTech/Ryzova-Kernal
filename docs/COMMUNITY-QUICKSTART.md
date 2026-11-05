# Community quickstart — Ryzova Kernel

**Audience:** developers and reviewers exploring the public source. This is not an installer, consumer release, complete build guide, or hardware support claim.

## 1. Inspect and test source on a normal development machine

Prerequisites: Git (with full history), Bash and Python 3. The commands below run provenance and host-level unit tests; **they do not boot Ryzova Kernel**.

```sh
git clone https://github.com/RyzovaTech/Ryzova-Kernal.git
cd Ryzova-Kernal
bash scripts/verify-foundation.sh
python3 -m unittest discover -s tests -p 'test_compact_contract_v1.py' -v
```

The provenance script checks that required source files and license notices exist and the pinned 9front Git history is present. It does **not** compile the kernel. The Python test exercises only the Phase 9.1 declarative Compact environment contract, not app execution or an operating system.

For more host-level research tests, browse the `tests/` directory and the corresponding CI workflows. Many require native toolchains, QEMU, privileged Linux network namespaces or other specialized environments; do not assume every test can run without setup.

## 2. Understand what actually boots

The project has demonstrated **native AMD64 source build and fresh QEMU boot** in CI, using the 9front toolchain and an isolated guest image. The evidence includes kernel identity, Plan 9 `rc`, namespace behavior, 9P ramfs, virtual network checks and matching kernel SHA-256 across the compiled guest file, installed guest file and host-extracted file.

To inspect or reproduce the documented procedure:

1. Read [docs/BUILD.md](BUILD.md) for the Plan 9 `mk` environment and source path `sys/src/9/pc64/`.
2. Read [the native build workflow](../.github/workflows/phase3-native-build.yml), which pins its input guest image, provisions QEMU and runs `scripts/phase3-native-build.py`.
3. Review [the Phase 3.5 verification and release gates](PHASE3-5-RELEASE-GATES.md), and examine a successful workflow run on the [Actions page](https://github.com/RyzovaTech/Ryzova-Kernal/actions/workflows/phase3-native-build.yml).
4. Do not redistribute an extracted kernel binary or image under the project's name without resolving the documented licensing and publication gates.

**Important limitation:** There is not yet a verified one-command, externally reproducible install or publicly authorized binary release. Reproducing the source-built QEMU path requires the pinned 9front environment, QEMU dependencies, the workflow's specific build procedure, and sufficient machine resources. We welcome independently reproduced evidence.

## 3. What to send if something fails

Report a [bug](https://github.com/RyzovaTech/Ryzova-Kernal/issues/new) with:

- exact Ryzova commit SHA and host OS / toolchain versions;
- command and reproducible steps;
- expected and actual output, with non-sensitive logs;
- whether it is a host test, QEMU guest test, or physical-hardware result;
- which checks passed, failed, or were not run.

Security vulnerabilities should follow [SECURITY.md](../SECURITY.md), not a public exploit-bearing report.

## 4. Where to help

Useful first contributions include docs corrections, a reproducible developer setup, reviewing the licence/provenance inventory, CI evidence improvements, bounded device-family testing and additional independently tested QEMU/physical hardware results. Consult [CONTRIBUTING.md](../CONTRIBUTING.md).

For a summary of current evidence versus research and draft PRs, see [PROJECT-STATUS.md](PROJECT-STATUS.md).
