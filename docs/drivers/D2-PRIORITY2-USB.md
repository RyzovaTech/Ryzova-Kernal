<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D2 Priority 2 — USB xHCI bounds and capacity hardening

- Reject invalid port indices (zero, negative or greater than enumerated port count) before reading/writing xHCI port MMIO for status, enable, reset, warm reset and power operations.
- When scanned controllers exceed the fixed supported controller array capacity, unmap the unused BAR MMIO and free controller state.
- Preserve original USB behavior for valid ports and available controller slots.
- Regression tests here check source invariants only. AMD64 build, QEMU USB keyboard/mouse/storage tests, unplug/replug, error injection and physical device lab verification remain required.
- No additional USB controller or device compatibility is claimed.
