# SPDX-License-Identifier: AGPL-3.0-only
# Read-only inventory. This does not boot, install or certify Ryzova Kernel.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-zA-Z0-9_-]{1,48}$')]
    [string]$MachineLabel,
    [string]$OutputPath = '.\ryzova-hardware-preflight.json'
)
$ErrorActionPreference = 'Stop'
$cpu = @(Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer,
    NumberOfCores, NumberOfLogicalProcessors)
$board = @(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, Version)
$bios = @(Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate)
$memory = @(Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Speed,
    ConfiguredClockSpeed, Manufacturer, PartNumber)
$disks = @(Get-CimInstance Win32_DiskDrive | Select-Object Model, InterfaceType, Size, FirmwareRevision)
$devices = @()
foreach ($device in Get-PnpDevice -PresentOnly) {
    if ($device.Class -notin @('Net','Display','HDC','SCSIAdapter','USB','MEDIA','System')) { continue }
    $ids = @()
    try {
        $ids = @((Get-PnpDeviceProperty -InstanceId $device.InstanceId `
            -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction Stop).Data |
            Where-Object { $_ -match '^(PCI|USB)\\' } | Sort-Object -Unique)
    } catch { continue }
    if ($ids.Count -eq 0) { continue }
    $devices += [ordered]@{ class=$device.Class; name=$device.FriendlyName; hardware_ids=$ids }
}
$secureBoot = 'unavailable'
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {}
$report = [ordered]@{
    schema='ryzova-windows-hardware-preflight/v1'
    machine_label=$MachineLabel
    collected_at_utc=(Get-Date).ToUniversalTime().ToString('o')
    collector_platform='Windows; inventory only'
    cpu=$cpu; motherboard=$board; firmware=$bios; memory=$memory; disks=$disks
    pci_usb_devices=$devices; secure_boot=$secureBoot
    ryzova_boot_tested=$false; physical_hardware_qualified=$false
    note='No host/user names, machine serials, UUIDs, disk serials, MAC/IP addresses or credentials collected.'
}
$json = $report | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath),
    $json, [System.Text.UTF8Encoding]::new($false))
Write-Output "Saved inventory: $OutputPath"
Write-Output 'Ryzova boot, storage integrity, network, USB, SMP and recovery tests are still required.'
