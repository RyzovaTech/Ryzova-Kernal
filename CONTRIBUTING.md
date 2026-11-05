# Contributing to Ryzova Kernel

Ryzova Kernel is an experimental **9front-derived** project. We welcome thoughtful, independently testable changes that improve reliability, hardware support, documentation and research quality. Preserve upstream history, contributor credit and all third-party notices.

**First-time contributors:** [community quickstart](docs/COMMUNITY-QUICKSTART.md) · [current status](docs/PROJECT-STATUS.md) · [build standards](docs/BUILD-STANDARDS.md) · [license map](LICENSE.md).

## Before opening a pull request

1. Check [existing issues](https://github.com/RyzovaTech/Ryzova-Kernal/issues) and [open PRs](https://github.com/RyzovaTech/Ryzova-Kernal/pulls) for overlapping work. Discuss a major design change in an issue (or GitHub Discussions once it is enabled).
2. Work from `main` on a topic branch. **Do not modify `upstream/front`**; that branch preserves historical source provenance, not an automatic sync channel.
3. State whether your changes are `Upstream import`, `Ryzova-owned` or `Third-party`. Name every material external source; maintain original copyright notices.
4. Use accurate file-level SPDX identifiers for newly authored files. Consult [LICENSE.md](LICENSE.md) and [docs/CONTRIBUTOR-LICENSING.md](docs/CONTRIBUTOR-LICENSING.md). A GPLv3 transition has been proposed for eligible Ryzova-controlled code, **but the existing file-level AGPL and third-party terms still apply until individually and lawfully updated**. See [the migration checklist](docs/LICENSING-TRANSITION.md).
5. Explain architecture and ABI effects, threat boundaries, hardware assumptions and regressions. Include exact commit SHA and test commands/logs. If only host-side parser tests pass, do **not** claim the native kernel feature works.
6. For AMD64 kernel or driver changes, preserve or extend the source-built QEMU build and boot checks. For ARM64 and hardware support, distinguish virtual/source checks from physical-device verification.
7. Open a PR with a short scope, evidence, limitations and risk analysis. A passing CI run does not authorize a binary release or prove production readiness.

## Useful contribution categories

- Better documented QEMU steps that a new contributor can actually reproduce;
- Small bug fixes with a regression test and proof of affected paths;
- Host-side parser and safety hardening without expanding compatibility claims;
- Native AMD64 test evidence, legacy PC preservation, independent hardware trials;
- Provenance, licensing, attribution and security documentation.

## Rights, AI-assisted work and attribution

Contributions must be yours to submit or supported by authorization from the relevant rights holders. **Contributing does not automatically assign copyright or grant Ryzova proprietary/commercial relicensing rights.** A separate, adequate written agreement is required when those additional rights are necessary. See [contributor licensing](docs/CONTRIBUTOR-LICENSING.md).

All submitted code, including code produced with assistive tools, must be reviewed, accurately attributed, tested and legally permissible to submit. The upstream 9front project maintains its own [contribution terms](lib/legal/contributing), including a restriction on computer-generated code **submitted to 9front**. Ryzova contributions are not automatically upstream submissions; verify upstream rules separately.

## Security and conduct

Use [SECURITY.md](SECURITY.md) for suspected vulnerabilities; do not post sensitive exploit details publicly. Be constructive and specific in technical discussion. Maintainers may decline changes whose test evidence, provenance or required license rights cannot be established.
