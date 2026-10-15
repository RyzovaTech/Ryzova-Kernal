# Ryzova Kernel — native identity device (Phase 3.1–3.2)

The Ryzova-derived kernel provides a **read-only Plan 9 device** via the kernel device selector `#Z`. The selector is in the **process namespace**, not a new Linux/Windows syscall. This foundation intentionally reuses 9front's ordinary kernel device APIs.

| Native 9front path | Example contents | Meaning |
| --- | --- | --- |
| `#Z/version` | `Ryzova Kernel 0.1.0-dev` | Kernel project/version identity |
| `#Z/foundation` | `9front-derived` | Preserve original architectural attribution |
| `#Z/abi` | `experimental-0` | Interface explicitly not stable yet |

From a 9front `rc` shell:

```rc
cat '#Z/version'
cat '#Z/foundation'
cat '#Z/abi'
```

A downstream distribution can optionally mount/bind this device in its own user namespace (for example, to `/dev/ryzova`), but **no global namespace changes** are imposed in Phase 3. The device is read-only for all users and does not expose configuration or privilege-escalation controls.

The only upstream code configuration change necessary is adding the `ryzova` device line in `sys/src/9/pc64/pc64`. The newly authored driver is separately AGPLv3-marked; original 9front source notices remain untouched.

All paths and values are experimental; ABI compatibility is not promised yet. This is **not** Linux/Windows/macOS binary compatibility. New syscall numbers are intentionally avoided.
