# Compact macOS M2

The M2 launch command accepts the exact project-owned x86-64 executable from
[M1's macOS 15.7.9 reference job](https://github.com/RyzovaTech/Ryzova-Kernal/actions/runs/41956142576/artifacts/13383002795).
Its source is `tests/fixtures/macos_m1_reference.c`. The checked-in fixture
retains the original bytes and the launcher gates admission by the whole-file
SHA-256. A rebuild requires independent qualification and a profile update.

The interpreter maps the fixture's segments into fixed private guest backing
arrays at a different guest base. It leaves PAGEZERO unmapped, reads LC_MAIN,
and resolves the single chained bind for `libSystem`'s `_write` to a bounded
console bridge. It implements only the x86-64 forms exercised by the reference,
with a 64-instruction budget, a 4 KiB private stack and 256 bytes of output.
Guest execution occurs in the interpreter, and the only bridge accepts stdout
and bytes in the guest text mapping. Guest return status is reported explicitly
by the Plan 9 launcher and propagated as the process exit status by the hosted
test launcher.

This fixture-specific loader trusts its layout only after the digest matches.
The M1 metadata admission profile remains the separate parser for untrusted
inputs. General Mach-O loading, generic chained fixups, Darwin syscalls and
namespace-backed file operations are outside the M2 profile.
