# Ryzova Kernel — public project status

*Community-facing evidence map, reviewed against `main` and open PRs on 2026-11-05. Feature branches and CI statuses change; recheck the relevant commit, PR and workflow before citing results.*

## Current verified foundation

| Area | Evidence scope | Not established |
| --- | --- | --- |
| AMD64 source kernel | Built with native 9front tooling and freshly booted under QEMU; bounded process, identity, namespace, ramfs/9P and network checks | Physical PC qualification, long-running security/reliability, end-user release |
| Source provenance | Imported 9front ancestry and license notices; automatic upstream synchronization disabled | Blanket legal clearance for every file/redistributable asset |
| Kernel regression infrastructure | Main-branch CI workflows and recorded QEMU artifacts, linked from `README.md` and `docs/BUILD.md` | Every hardware platform or every in-progress PR passing an exact-head native test |
| Experimental remote-resource work | Scoped host-side 9P, TLS, cache and coordination tests; some native guest QEMU evidence | Production distributed scheduling, arbitrary remote program execution, secure multi-tenant cloud |
| Application-compatibility research | Bounded Linux ELF interpreters and narrow native/host integration tests; PE/Mach-O structural investigation | General Linux, Windows or macOS executable compatibility |
| Driver modernization | Safety checks, ID inventories and specific controller families | A verified number of hardware models supported; modern GPU, Wi-Fi and laptop compatibility certification |
| ARM64 | Source-oriented architecture, server and regression research | General physical ARM64 boot/support certification |

Read the exact acceptance documents before upgrading any claim: [Phase 3.5](PHASE3-5-RELEASE-GATES.md), [Phase 5 closeout](PHASE5-9-CLOSEOUT.md), [Phase 6 native QEMU](PHASE6-NATIVE-QEMU-HANDOFF.md), [Phase 8.2](PHASE8-2-MULTINODE-EXECUTION.md), and [Phase 9.2](PHASE9-2-COMPACT-NATIVE.md).

## Work in progress is not shipped support

At the time of this review, draft PRs include:

- [Linux Priority 1](https://github.com/RyzovaTech/Ryzova-Kernal/pull/81) — not accepted for general Linux compatibility;
- [Windows W7–W9](https://github.com/RyzovaTech/Ryzova-Kernal/pull/89) — research and bounded APIs, not a Windows app compatibility guarantee;
- [macOS MAC series](https://github.com/RyzovaTech/Ryzova-Kernal/pull/90) — narrow Mach-O-related progress, not full macOS execution;
- [ARM64 M5/M6](https://github.com/RyzovaTech/Ryzova-Kernal/pulls) — native-runtime, IO and hardware evidence gates remain important;
- [driver engineering](https://github.com/RyzovaTech/Ryzova-Kernal/pulls) — branch-specific safety improvements require independent review.

A PR may have useful unit tests and still fail to prove an externally usable native kernel feature. Cite exact SHA and test artifact for claims.

## Public release and community blockers

- [ ] Independently reproducible, low-friction QEMU demonstration for a new developer.
- [ ] Review third-party redistribution and contributor rights, with an authorized public release decision. [Legal issue #3](https://github.com/RyzovaTech/Ryzova-Kernal/issues/3), [release issue #9](https://github.com/RyzovaTech/Ryzova-Kernal/issues/9).
- [ ] Complete rights-reviewed AGPLv3-to-GPLv3 migration for eligible Ryzova-owned code; distinguish actual file headers from proposed policy. [Licensing transition](LICENSING-TRANSITION.md).
- [ ] Enable GitHub Discussions and add an initial welcome thread. (GitHub **Settings → Features → Discussions**.)
- [ ] Add a concise repository description and discoverability topics in GitHub settings.
- [ ] Confirm main branch protection, security reporting setup and source-built QEMU checks required for merge.
- [ ] Independent physical hardware, external network, hardware-driver and security qualification before making stronger product claims. [Issues](https://github.com/RyzovaTech/Ryzova-Kernal/issues).

**A source repository may be useful to discuss before a binary release.** However, the [official Show HN rules](https://news.ycombinator.com/showhn.html) ask that other people can actually try the work. Before a Show HN submission, have an externally testable, honestly documented source/QEMU demonstration; otherwise use a normal technical HN discussion submission.

## Naming and attribution

Ryzova Kernel is **derived from 9front / Plan 9**. Do not imply original invention of the inherited code or affiliation with upstream. Preserve history, license texts, attributions and original notices. See [UPSTREAM.md](UPSTREAM.md), [LICENSE.md](../LICENSE.md) and [TRADEMARKS.md](../TRADEMARKS.md).
