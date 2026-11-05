# Security policy

**Project maturity:** Ryzova Kernel is an experimental 9front-derived project. Its source-built AMD64 kernel has passed bounded QEMU boot and functional smoke tests. **That does not constitute a security certification**, production support guarantee, hardware qualification, supported binary release, or published security-response SLA.

## Reporting a vulnerability

Please do **not** post working exploits, sensitive credentials, or exploit-bearing details in a public GitHub issue or pull request.

Use a **private GitHub vulnerability report** if the repository has enabled that feature. Otherwise contact maintainers only through a private channel they have explicitly published. If neither is available, request that maintainers configure private vulnerability reporting; do not assume an unpublished contact address exists.

Include affected commits, a minimal reproduction where safe, expected and actual behavior, potential impact, and any mitigation. Upstream 9front issues should be coordinated responsibly with the upstream maintainers when appropriate.

## Security boundaries

Host-side prototypes, QEMU acceptance tests, parser rejection checks and TLS research do not establish a hardened multi-tenant production environment. Physical platforms, third-party redistribution, secure update channels and long-term adversarial testing remain separate qualification work.

Automatic 9front synchronization is disabled: security fixes are not silently inherited. See [docs/UPSTREAM.md](docs/UPSTREAM.md) and [project status](docs/PROJECT-STATUS.md).
