# Contributing to Ryzova Kernel

Ryzova Kernel is a 9front-derived source project. Please preserve upstream history and observe all third-party notices. Read [`LICENSE.md`](LICENSE.md), [`docs/CONTRIBUTOR-LICENSING.md`](docs/CONTRIBUTOR-LICENSING.md) and [`docs/BUILD-STANDARDS.md`](docs/BUILD-STANDARDS.md) before submitting changes.

## Contribution workflow

1. Open an issue or discussion describing the change and its motivation.
2. Work on a topic branch; target `main` through a pull request.
3. **Do not modify `upstream/front`.** It is an exact tracked upstream branch.
4. Label modifications clearly: `Upstream import`, `Ryzova-owned`, or `Third-party`, with source origin and license details.
5. Use an SPDX identifier for newly authored source; retain upstream copyright statements.
6. Include build and runtime test evidence where feasible; identify anything not tested. Do not claim CI source checks prove a kernel can boot.
7. Document architecture-specific effects, ABI changes, and security implications.

## Contributor rights

A code contribution must be yours to submit (or properly authorized) and accurately credited. **No assignment or commercial relicensing is silently assumed.** For new AGPL-marked contributions, the inbound license is AGPLv3 unless a separate, explicit agreement is signed. To incorporate a contribution into a separately commercially licensed component, a legally adequate additional grant is required before accepting it for that component. See [contributor licensing policy](docs/CONTRIBUTOR-LICENSING.md).

The upstream 9front project has its **own** [contribution conditions](lib/legal/contributing), including a restriction on computer-generated code submitted **to 9front**. Ryzova submissions are not automatically upstream submissions. Check and comply with upstream policy independently if proposing work upstream.

## Security and conduct

Do not publish exploitable security issues in public PRs before private disclosure. Consult [`SECURITY.md`](SECURITY.md). Participate constructively and respectfully.

Maintainers may defer a change if provenance, legal compatibility, tests, or rights needed for its intended distribution have not been established.
