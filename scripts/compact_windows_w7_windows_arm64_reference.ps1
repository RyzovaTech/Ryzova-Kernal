# SPDX-License-Identifier: AGPL-3.0-only
# W7: REAL Windows ARM64 OS host reference for the same four original,
# import-free Clang/LLD Windows ARM64 PE32+ C programs as the ISA interpreter.
# An actual Windows ARM64 host is not a native Ryzova ARM64 kernel.
param(
  [Parameter(Mandatory=$true)][string]$OutDir,
  [Parameter(Mandatory=$true)][string]$SourceCommit
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -ne 'Arm64') { throw "Genuine Windows ARM64 OS required, got $arch" }
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows)) {
  throw 'Windows OS required'
}
if ($SourceCommit -notmatch '^[a-f0-9]{40}$') {
  throw 'Exact 40-hex source commit must be pinned'
}
if (-not (Get-Command clang -ErrorAction SilentlyContinue)) { throw 'LLVM clang not installed' }
if (-not (Get-Command lld-link -ErrorAction SilentlyContinue)) { throw 'LLVM ARM64 PE linker not installed' }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$target = (Resolve-Path $OutDir).Path
$source = [ordered]@{
  integer = 'tests/fixtures/windows_w7_arm64_reference.c'
  call = 'tests/fixtures/windows_w7_arm64_call_reference.c'
}
$cases = [ordered]@{}
$emptyHash = [Convert]::ToHexString(
  [Security.Cryptography.SHA256]::HashData([byte[]]@())
).ToLowerInvariant()

foreach ($label in $source.Keys) {
  $name = $source[$label]
  $sourceFile = (Resolve-Path $name).Path
  $sourceSha = (Get-FileHash $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
  foreach ($optimization in @('O0','O2')) {
    $case = "$label-$optimization"
    $object = Join-Path $target "$case.obj"
    $executable = Join-Path $target "$case.exe"

    & clang --target=aarch64-windows-msvc "-$optimization" -c "$sourceFile" -o "$object"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $object)) {
      throw "Clang real Windows ARM64 object compilation failed for $case"
    }
    & lld-link /machine:arm64 /entry:main /subsystem:console /nodefaultlib "/out:$executable" "$object"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $executable)) {
      throw "Clang/LLD Windows ARM64 link failed for $case"
    }

    $bytes = [IO.File]::ReadAllBytes($executable)
    if ($bytes.Length -lt 256 -or $bytes.Length -gt (4*1024*1024) -or
        $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
      throw "Invalid bounded PE for $case"
    }
    $nt = [BitConverter]::ToInt32($bytes,0x3c)
    if ($nt -lt 0 -or $nt -gt ($bytes.Length-160) -or
        $bytes[$nt] -ne 0x50 -or $bytes[$nt+1] -ne 0x45 -or
        [BitConverter]::ToUInt16($bytes,$nt+4) -ne 0xaa64 -or
        [BitConverter]::ToUInt16($bytes,$nt+24) -ne 0x20b -or
        [BitConverter]::ToUInt16($bytes,$nt+24+68) -ne 3) {
      throw "Not original classic ARM64 Windows PE32+ console: $case"
    }
    # No imports, including no opaque Windows ARM64 API thunk.
    $opt = $nt+24
    if ([BitConverter]::ToUInt32($bytes,$opt+108) -lt 2 -or
        [BitConverter]::ToUInt32($bytes,$opt+112+8) -ne 0 -or
        [BitConverter]::ToUInt32($bytes,$opt+112+12) -ne 0) {
      throw "Unreviewed Windows imports in $case"
    }

    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $executable
    $start.WorkingDirectory = $target
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($start)
    if ($null -eq $proc) { throw "Windows ARM64 failed to start $case" }
    if (-not $proc.WaitForExit(15000)) {
      $proc.Kill($true)
      throw "Windows ARM64 execution timed out: $case"
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    if ($proc.ExitCode -ne 37 -or $stdout -ne '' -or $stderr -ne '') {
      throw "Real Windows ARM64 runtime mismatch: $case exit=$($proc.ExitCode)"
    }
    $peSha = (Get-FileHash $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    $cases[$case] = [ordered]@{
      source_sha256 = $sourceSha
      windows_arm64_pe_sha256 = $peSha
      windows_arm64_pe_bytes = $bytes.Length
      actual_windows_arm64_exit = $proc.ExitCode
      actual_windows_arm64_stdout_sha256 = $emptyHash
      actual_windows_arm64_stderr_sha256 = $emptyHash
      actual_windows_arm64_native_host_passed = $true
    }
    Write-Output "W7_NATIVE_WINDOWS_ARM64_HOST case=$case exit=37 sha256=$peSha"
  }
}
if ($cases.Count -ne 4) { throw 'Not all four real Windows ARM64 executions passed' }
$report = [ordered]@{
  schema = 'compact-windows-w7-native-windows-arm64-host/v1'
  source_commit = $SourceCommit
  windows_os_architecture = 'Arm64'
  windows_os_version = [Environment]::OSVersion.VersionString
  windows_runner_image_version = $env:ImageVersion
  cases = $cases
  actual_windows_arm64_host_reference_qualified = $true
  native_ryzova_arm64_kernel_boot_qualified = $false
  windows_v1_release_qualified = $false
  physical_arm64_hardware_qualified = $false
}
$report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $target 'windows-arm64-reference.json') -Encoding utf8
Write-Output 'W7_NATIVE_WINDOWS_ARM64_HOST 4/4 PASS (Ryzova ARM64 kernel NOT qualified)'
