<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# First physical PC qualification: evidence, not a support claim

The owner has selected their physical PC as the first test target. Its exact
configuration must be collected; prior conversational CPU/RAM descriptions
are not hardware evidence. No physical machine was accessed from CI, and no
physical test record or certification has been added.

## 1. Inventory from Windows (read only)

Open PowerShell in the repository and run:

```powershell
& .\scripts\collect-windows-hardware.ps1 -MachineLabel first-pc
```

The collector reads CPU/core counts, motherboard model, BIOS version, memory,
disk models and PCI/USB hardware IDs. It excludes machine and disk serials,
host/user names, UUIDs, MAC/IP addresses and credentials. It does not change
boot settings, drivers, partition tables, firmware or installed applications.
Secure Boot may be reported unavailable when permission/platform support is
missing. Inventory collection does not establish driver functionality.

## 2. Select a recoverable boot method after inventory review

Check actual motherboard boot support, controller IDs, available removable
media, backup/recovery access and the exact source-built kernel digest.
Use a separate test disk/removable medium and keep normal system disks out
of write tests. Do not repartition or overwrite the Windows/system disk.
No ready-to-boot physical image is provided by this change; source build,
artifact rights review and release authorization remain separate gates.

## 3. Real Ryzova boot evidence required

Record exact source SHA, independent SHA-256 of the boot image, toolchain,
firmware settings, boot method and serial/console logs from the physical PC.
After native boot, collect read-only `#Z/version`, `#Z/abi`, `/dev/sysstat`,
`/dev/swap`, `#P/drivercandidates`, `/dev/sdctl` and network/device enumeration
where available. Missing interfaces or failed commands are failures/unknowns,
not evidence of support. Never print credential/key files in captured logs.

Qualification then requires observed results for storage read/write digest
integrity on the separate scratch disk, network transfer/reconnect integrity,
USB input and hotplug, memory pressure, SMP progress/IRQ teardown, cold boot,
reboot and recovery. Record workload, duration, device IDs, errors and logs
for each test. CI/QEMU and source-ID matches cannot replace these results.

Only after independent evidence review should the exact machine/configuration
be considered for `ryzova/drivers/physical-tests.json`. A successful boot alone
does not certify every onboard device or authorize public binary release.
