# Security policy — Ryzova Kernel

## Project maturity and supported versions

**Ryzova Kernel is experimental systems software, not a production-supported operating system.** Source-built AMD64 kernel boot in QEMU and selected compatibility/9P tests have been demonstrated, but this is **not** a security audit, supported hardware platform, hardened production release, or promise of complete Linux/Windows/macOS compatibility.

| Version or deployment | Security support status |
| --- | --- |
| Current `main` source and reproducible research branches | Best-effort review of credible reports; no guaranteed response or fix schedule |
| Historical commits or branches | No guaranteed backports |
| Boot images, ISOs and distributed production installations | No officially supported public release or security-update channel |

No paid security support, response-time SLA, bounty program or vulnerability-fix guarantee is offered.

## Reporting a vulnerability privately

**Please do not post exploit details, credentials, sensitive traces, or a working exploit in a public GitHub Issue, Discussion or Pull Request.**

1. Prefer GitHub's **Report a vulnerability** workflow under [Security → Advisories](https://github.com/RyzovaTech/Ryzova-Kernel/security/advisories), **if private vulnerability reporting has been enabled by the repository owner**.
2. If the private-reporting action is unavailable, there is **no verified private contact address published by this policy**. Maintainers should enable GitHub Private Vulnerability Reporting (repository Settings → Security / Code security settings) or publish a trustworthy private disclosure channel before requesting sensitive vulnerability details.
3. Do not disclose a sensitive proof of concept publicly just to obtain an acknowledgement. If disclosure cannot be made privately here, use an appropriate upstream or coordinated disclosure route where relevant.

The reporting route should be checked on GitHub before sending sensitive details; this document does not claim that private reporting is currently enabled.

## Include in a private report

Provide the affected file/area, commit SHA, environment (architecture/QEMU/toolchain), expected versus observed behavior, security impact, and minimal steps or a bounded proof of concept. If known, include mitigation suggestions and whether the issue also exists in upstream 9front. Avoid publishing secrets, private keys, or personal data.

Relevant areas include Ryzova-added kernel interfaces, compatibility parsers/interpreters, driver integration, remote 9P/TLS services, identity/grant boundaries, memory safety and concurrency.

## Coordination and disclosure

Reports are triaged on a **best-effort** basis. Maintainers may request reproduction or further details, investigate severity, and coordinate a patch, advisory and disclosure timing with the reporter. **No acknowledgement or resolution deadline is promised.** Reporting does not transfer intellectual-property rights or guarantee acceptance of a proposed fix.

If the issue originates in inherited 9front or another third-party component, coordinate with the relevant upstream maintainers and follow their disclosure preferences; Ryzova cannot promise upstream remediation. Keep unpublished security details private until an appropriate coordinated disclosure.

## Supported security assertions and limitations

- CI results validate **specific tests on specific revisions**, not universal security, memory safety or physical-hardware reliability.
- QEMU boot evidence is **not** proof of arbitrary AMD64 hardware support or production safety.
- Selected Linux/Windows/macOS workload interpretation is **not** a sandbox guarantee.
- Avoid testing against systems, users, networks or devices you do not own or have explicit authorization to assess.
- An upstream merge does **not** automatically deliver a security update or approved release.

For project maturity and reproducible tests see [README.md](README.md), [docs/BUILD.md](docs/BUILD.md), [docs/UPSTREAM.md](docs/UPSTREAM.md), and [CONTRIBUTING.md](CONTRIBUTING.md).
