# Contributing to Ryzova Kernel

Thanks for considering a contribution. **Ryzova Kernel is an experimental 9front-derived kernel and systems-software research project**, with bounded compatibility environments and 9P-based resource experiments. It is **not** a finished OS distribution. We particularly value independent reproduction, precise bug reports, focused architecture critiques, tests and small reviewable improvements.

Start with the [README](README.md), [MIT/GPLv3 license map](LICENSE.md), [build guide](docs/BUILD.md), [build standards](docs/BUILD-STANDARDS.md), and [security policy](SECURITY.md).

## Where to participate

| What you want to do | Best place |
| --- | --- |
| Ask an architecture/design question or explore an idea | GitHub Discussions **if enabled**; otherwise an appropriately scoped Issue |
| Report a reproducible non-security bug or missing documentation | [GitHub Issues](https://github.com/RyzovaTech/Ryzova-Kernel/issues) |
| Suggest a narrow code, test or documentation fix | Open an Issue for complex changes, then a focused Pull Request |
| Report a potentially exploitable vulnerability | Follow [SECURITY.md](SECURITY.md), **not** a public issue or discussion |
| Submit code to the upstream 9front project | Follow **9front's own contribution rules**, not Ryzova's rules alone |

For substantial work, describe a proposed interface, intended scope, upstream differences, failure modes and acceptance tests before investing heavily in implementation. No issue, discussion or feature proposal guarantees maintainer acceptance.

## First contribution: reproduce the evidence

A good starting point is to reproduce one narrowly documented test or improve the reproducibility of its instructions.

1. Fork the repository and work from the latest `main` on a topic branch.
2. Read [`docs/BUILD.md`](docs/BUILD.md) for the Plan 9/9front toolchain and native QEMU build setup. **The kernel is not compiled using a standard Linux GNU Make workflow.**
3. Run relevant source-level checks on a full checkout, for example:

   ```sh
   python3 scripts/audit_licenses.py
   python3 scripts/check-identity.py
   python3 scripts/m0_native_rules.py --check
   bash scripts/verify-foundation.sh
   ```

4. Run only the tests appropriate to your change and environment. Provide exact commands, the tested commit, toolchain/QEMU versions if relevant, and logs or results.
5. State clearly if the change has **not** been built on native 9front tools, booted in QEMU, or tested on physical hardware. A passing static or unit test does not prove a successful kernel boot.

See the existing [GitHub Actions workflows](.github/workflows/) for the targeted test suites. Some tests depend on pinned images, architectures, external fixtures or other expensive setup; do not report an unrun test as passing.

## Code and design guidelines

- **Keep upstream identifiable:** preserve the complete 9front/Plan 9 history, attribution and license notices. Do not change the tracked `upstream/front` branch as part of a normal Ryzova feature PR.
- **Prefer focused changes:** isolate platform drivers, kernel devices, 9P/remote services, compatibility interpreters and tests into understandable PRs.
- **Describe safety:** document memory safety, synchronization, resource limits, trust boundaries, permission handling, ABI changes and failure recovery when relevant.
- **Support your claims:** distinguish native-kernel behavior from user-space emulation/interpreters and demonstrated workloads from proposed future features.
- **Minimize scope:** do not promise compatibility with arbitrary Linux, Windows or macOS applications based on a few selected fixtures.

## Source origin, AI assistance and licensing

Human-directed, AI-assisted development is welcome **subject to the same correctness, testing, provenance and security standards as any other contribution**. For substantive AI-generated or AI-edited code, summarize which parts were assisted, how you reviewed the result, and what tests you actually performed. **Do not submit code you cannot adequately review or explain, or material whose rights and origin you cannot establish.** Do not insert generated copies of copyrighted third-party code without valid permission.

Every contribution must be your own work or material you are authorized to submit. Record upstream derivation, third-party dependencies, copied snippets and generated components. Keep all existing file-level copyright and license notices intact.

- Newly authored, rights-controlled **Ryzova-origin** source is intended to use `SPDX-License-Identifier: GPL-3.0-only` when all necessary copyright holders authorize that license; see [`LICENSE.md`](LICENSE.md) and [contributor licensing rules](docs/CONTRIBUTOR-LICENSING.md).
- Existing upstream 9front/Plan 9 code remains under its own MIT terms and exceptions; third-party assets retain their original licenses.
- Historical AGPLv3 public grants remain valid. Do not casually relicense existing files without a documented rights check.
- **There is no separate proprietary relicensing program** and **no silent copyright assignment** by opening a Pull Request.
- **Upstream warning:** [9front's contributor conditions](lib/legal/contributing) include restrictions on submitting computer-generated code **to 9front itself**. Ryzova contributions do not become eligible for upstream submission just because Ryzova accepts them. Comply with upstream rules separately.

## Pull Request checklist

Before opening a PR, confirm that you have:

- [ ] Explained the problem, scope, design and evidence for your change.
- [ ] Identified whether each touched area is **upstream**, **Ryzova-origin**, or **third-party**, and preserved the appropriate licenses.
- [ ] Disclosed substantive AI/tool assistance and checked source provenance if applicable.
- [ ] Included tests, commands, environment and outcomes, with **untested scenarios explicitly identified**.
- [ ] Considered memory/permission/security/ABI impacts and known regressions.
- [ ] Updated documentation and user-facing claims where behavior changes.
- [ ] Avoided publishing sensitive vulnerability details in a public PR.

Open a PR against `main`, link the relevant issue where possible and respond constructively to review feedback. Maintainers can ask for narrower scope, additional evidence or revisions; they may defer changes if needed rights or safety evidence are absent.

## Security and respectful collaboration

Use [SECURITY.md](SECURITY.md) for private vulnerability reporting. Avoid publicly posting sensitive exploits, secrets or third-party personal information. Technical criticism is welcome; harassment and personal attacks are not. The project does not guarantee that every issue, PR or discussion will receive an immediate response.

**Useful first contributions:** independently rerunning a pinned QEMU check, clarifying the 9front-vs-Ryzova source boundary, fixing a reproducible test, reviewing a narrowly scoped 9P permission boundary, or improving license provenance documentation.
