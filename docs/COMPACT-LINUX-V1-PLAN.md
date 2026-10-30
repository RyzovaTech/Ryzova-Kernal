# Compact Linux V1: completion contract and delivery phases

Manethගේ අරමුණ වන්නේ Flex මත application එකක් ලෙස ධාවනය වන Linux
application environment එකයි. මෙහි V1 completion එක නම් කළ application
workflows සහ acceptance gates මඟින් තීරණය වේ. Test ගණන හෝ අනුමාන
ප්‍රතිශතයක් completion ලෙස භාවිත නොකරයි.

Status: **CLX-01 and CLX-02 complete; CLX-03 is next; V1 is incomplete.** The machine
source of truth is [linux-v1-plan.json](../ryzova/compact/linux-v1-plan.json).
New CLX phase numbers are distinct from historical Phase 9.1–9.16 PR numbering.

## Exact starting point and integration audit

- Main: `0a09a9833c895172e359a1d89216fc0a81e4eaf2` (earlier foundation PoC).
- Frozen staged baseline: PR #75, `4b2eb6b96fb54067754eef825271331f045cabdc`.
- All sixteen PR heads #60–#75 occur in that reference history, 48 commits ahead
  of main. They are drafts targeting main; no automatic merge is authorized.
- Reference CI: 31 successful workflows, 109 Phase 9 plus 63 Phase 5 methods.
  Its source-built native run is [41000789638](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41000789638).
  This is bounded-runtime evidence, not proof of the V1 application targets.
- [Audit snapshot](validation/compact-linux-v1-phase1-audit.json) records every
  PR head and observed workflow. Green CI does not establish branch-protection
  administration settings; that visibility remains unverified.

Review the cumulative change once for integration. Do not independently reapply
all sixteen overlapping PRs. Phase 8 may merge the reviewed descendant only after
separate user authorization; predecessor PR disposition is a review decision.
Historical contract-only and source-only documents describe their original phases
and remain historical evidence, rather than being rewritten as current claims.

The user subsequently authorized integration on 2026-10-30. PR #76 was merged
as `bd609ee7c0796ae56f74150553bbd82a05efbf7c`; the bullets above retain the
original audit snapshot. [Phase 2 progress](COMPACT-LINUX-V1-PHASE2.md) records
the qualified root, live mounts, views/revocation and recovery profiles.

## What V1 means

V1 is an AMD64/QEMU developer environment with a Linux syscall ABI and selected
static/dynamic `x86_64-linux-musl` applications. It runs as a native Flex
application and uses Flex namespace/resource grants. Environment-level shared
resources and narrower per-application views must have explicit inheritance and
revocation rules. Linux is not silently substituted as the host execution engine.

Completion requires every acceptance ID below, on one final source revision, with
real artifacts and native execution evidence. A Python project means the declared
stdlib/multi-module workflows, not every package on PyPI. GCC means the actual C
compiler/toolchain below, not the existing freestanding TinyCC demonstration.

Excluded from this V1: arbitrary Linux/glibc binary compatibility, GUI/GPU/audio,
other GCC language frontends, arbitrary pip binary wheels, Windows/macOS,
operational ARM64 and physical hardware qualification. These become separately
scoped later phases. V1 functional acceptance cannot override the repository's
existing kernel rights, hardware, security or binary-publication release gates.
No public kernel binary is automatically authorized by this plan.

## Eight delivery phases

| Phase | Deliverable | Exit condition |
| --- | --- | --- |
| CLX-01 | Audit, frozen targets, finite checklist, baseline runner | Audited heads, version/workflow contract and exact-head baseline CI recorded |
| CLX-02 | Root tree and live filesystem resource mounts | Required directory/metadata operations, persistence, grant denial and isolation pass |
| CLX-03 | Memory, processes and measured resource profiles | Private COW/shared anonymous maps, required futex/session/resource APIs and stress tests pass |
| CLX-04 | AMD64/loader/library coverage | Actual target binaries load; their required CPU/FP/SIMD behavior passes differential tests |
| CLX-05 | DNS/UDP/IPv6, stream completeness and guest HTTPS | Real separate-peer transfers, TLS trust failures, routing denial and deadlines pass |
| CLX-06 | PTY, terminal and job control | Interactive shell handles input, Ctrl-C, resize and foreground/background jobs |
| CLX-07 | Named application workflows and artifact locks | BusyBox, Python, Git and C SDK workflows all pass with finite measured budgets |
| CLX-08 | Fresh installation/recovery and reviewed integration | Same-head complete acceptance, inherited regressions and separately authorized integration |

Application probes start during CLX-02, not only during CLX-07. Each failure is
classified as filesystem, memory/process, ISA/ABI, network or terminal, assigned
to its owning phase, fixed there and rerun against the same target version. A
phase exits on its evidence, not on the number of newly added features.

## Frozen application versions and workflows

| Target | Fixed version | Required V1 result |
| --- | --- | --- |
| BusyBox | 1.35.0 | Declared shell/file/search/archive/network applets and PTY ash jobs |
| CPython | 3.12.10 | Multi-module stdlib project, threads/processes/subprocess and socket/ssl exchange |
| Git | 2.49.0 | Persisted local repository operations and granted HTTPS clone/fetch/push |
| GCC | 14.2.0 | Guest C project and shared library compiled; produced ELF runs in the guest |
| Binutils | 2.43.1 | Guest assembler/linker and ELF/symbol inspection for that project |
| GNU Make | 4.4.1 | Clean and incremental C project builds using guest processes |
| musl | 1.2.6 | Required libc, startup, dynamic loader, TLS and pthread behavior |

These are fixed compatibility references, not claims of latest upstream releases.
Version changes require a reviewed plan revision and retained evidence. Build
configuration may be documented; application source must not be patched to fake
support. Replacing CPython with MicroPython or GCC with TinyCC does not satisfy
these gates. The existing BusyBox published binary remains a pinned regression
fixture; the V1 source build must explicitly enable the required applets and job
control if the regression binary's configuration is insufficient.

Top-level versions are frozen now. Full source checksums, transitive dependencies
(including guest TLS/HTTP, compression and GCC prerequisites), build recipes and
binary hashes are **not yet locked or built** for new targets. LOCKS remains a
required open gate. Complete those locks before application qualification; do not
resolve unspecified dependencies from the network during acceptance.

Upstream references: [CPython](https://www.python.org/downloads/release/python-31210/),
[Git archives](https://www.kernel.org/pub/software/scm/git/),
[GCC 14.2 announcement](https://gcc.gnu.org/pipermail/gcc-announce/2024/000184.html),
[Binutils 2.43.1 announcement](https://sourceware.org/pipermail/binutils/2024-August/136396.html),
[Make 4.4.1 announcement](https://lists.gnu.org/archive/html/info-gnu/2023-02/msg00011.html).

## Completion checklist: all seventeen are mandatory

| Gate | Owner | Required evidence |
| --- | --- | --- |
| FS-ROOT | CLX-02 | Declared /etc,/home,/usr,/var,/tmp tree; real project operations |
| FS-ISOLATION | CLX-02 | Per-view grants/inheritance; traversal/link/host-resource denial |
| FS-PERSIST | CLX-02 | Independent restart/reload, non-destructive failure and recovery |
| MEM-PROC | CLX-03 | Required private/shared memory, futex and process/session semantics |
| RESOURCE | CLX-03 | Per-target and aggregate finite resource budgets, enforced and measured |
| AMD64-ABI | CLX-04 | Required executable/library and instruction/FP/SIMD references |
| NET-PEERS | CLX-05 | Real separate-node DNS, IPv4/IPv6 TCP/UDP and failure cases |
| TLS-GUEST | CLX-05 | Guest certificate/hostname checks, bad trust and ungranted-route denial |
| TTY-JOBS | CLX-06 | Interactive PTY, signals, resize and job-control lifecycle |
| APP-BUSYBOX | CLX-07 | Every declared applet/script and interactive workflow |
| APP-PYTHON | CLX-07 | Declared project/module/thread/process/TLS workflows |
| APP-GIT | CLX-07 | Local and HTTPS repository workflows, matching persisted content |
| APP-C-SDK | CLX-07 | Actual GCC/binutils/make guest build and resulting ELF/library execution |
| LOCKS | CLX-07 | Complete sources, dependency/config/toolchain locks and binary digests |
| NATIVE-EVIDENCE | CLX-08 | Same-head source/fixture challenges and native kernel provenance |
| INSTALL-RECOVERY | CLX-08 | Fresh boot/install/launch/export/recovery reproduces the acceptance suite |
| INTEGRATION | CLX-08 | Inherited checks, cumulative review, authorization and release-policy boundary |

FS-ROOT, FS-ISOLATION and FS-PERSIST are now passed with the dedicated
[CLX-02 acceptance record](validation/compact-linux-v1-phase2-acceptance.json).
The other fourteen gates remain open. A green regression baseline alone still
does not qualify application workflows or complete V1.

## Known blockers mapped to work

| Current boundary | Source/evidence | Owner |
| --- | --- | --- |
| Root/live filesystem profile qualified; 32 slots and 64-KiB files still need measured developer budgets | syscall_vfs.h, filesystem_state.h | CLX-03 |
| Native live directory profile has explicit POSIX/durability limits; new filesystem requirements reopen its gate | COMPACT-LINUX-V1-PHASE2.md | CLX-02 if required by a target |
| Mutable-file private maps/shared anonymous memory/file futex keys unsupported | memory.c, jobs_threads.h | CLX-03 |
| 4-MiB images, 16-MiB address span, bounded steps/fds/tasks | process.h, jobs.h, namespace.h | CLX-03/04 |
| Integer/selected vector interpreter; unsupported instructions fail closed | cpu.c | CLX-04 |
| Exact IPv4 TCP grants; no guest DNS/UDP/IPv6 or external listeners | syscall_net.h, network_plan9.h | CLX-05 |
| Input snapshots/output callbacks; no interactive PTY | syscall.c, native_runner.c | CLX-06 |
| Python/Git/GCC/Make target workloads have no execution evidence | COMPACT-LINUX-STATUS.md | CLX-07 |

Measure target footprint/opcodes early. Larger developer profiles require explicit
bounded allocation and aggregate quotas; silently raising every limit or removing
limits is not completion. Actual image/RAM/instruction/time/fd/storage/network
budgets must be selected from measurements before CLX-07 can pass. No native-speed
or arbitrary-application promise is introduced.

## Repeat the baseline

From a full repository checkout, build/fetch the existing pinned fixtures:

```sh
python scripts/phase9_compiler.py --build artifacts/musl-fixtures
python scripts/phase9_shell.py --fetch artifacts/jobs-fixtures
python scripts/phase9_busybox.py --fetch artifacts/jobs-fixtures
python scripts/compact_linux_baseline.py --check-plan
python -m unittest discover -s tests -p 'test_compact_linux_plan.py' -v
COMPACT_MUSL_DIR=artifacts/musl-fixtures \
COMPACT_SHELL_DIR=artifacts/jobs-fixtures \
COMPACT_BUSYBOX_DIR=artifacts/jobs-fixtures \
python scripts/compact_linux_baseline.py --output artifacts/compact-linux-v1/baseline.json
```

The runner checks pinned fixture/source hashes, records built fixture hashes,
compiler/Python versions and actual runtime core digests, then runs the full
Phase 5 and Phase 9 suites. Missing fixtures, failures, incomplete discovery,
skips or disabled qualification checks prevent `regression_qualified=true`.
The frozen minimum is 63 Phase 5 plus 109 Phase 9 tests; later tests may increase
that floor. The separate ten plan tests guard against premature completion.

`--diagnostic` may run a restricted local environment, but always reports
`regression_qualified=false`. A successful diagnostic command is not qualification.
CI runs the strict mode and uploads baseline/suite JSON reports. The runner never
marks V1 complete, merges, or authorizes publication. Native QEMU/security/driver
checks remain separate, unchanged required evidence. Baseline JSON records the
current core and whether it matches the frozen reference; future implementation
changes may differ while still running the inherited regression suite.

## Phase 1 handoff

Deliverables are this contract, the machine plan, audited PR/history snapshot,
strict/diagnostic baseline runner, qualification guard tests and exact-head CI.
No new Linux compatibility feature belongs to this phase. Phase 2 starts with
FS-ROOT/FS-ISOLATION/FS-PERSIST, using the frozen application probes to expose real
filesystem blockers. A remaining gate gets an owner and evidence; it is not
replaced by another open-ended feature list.
