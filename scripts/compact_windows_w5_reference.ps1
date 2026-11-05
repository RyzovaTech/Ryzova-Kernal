# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root 'artifacts/compact-windows/w5-reference'
New-Item -ItemType Directory -Force $out | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$install) { throw 'MSVC x64 installation missing' }
$vcvars = Join-Path $install 'VC/Auxiliary/Build/vcvars64.bat'
$source = Join-Path $root 'tests/fixtures/windows_w5_reference.c'
# Metadata-only import library resolves the selected exports from the OS UCRT.
# No Microsoft DLL/library binary is transferred to the hosted runtime.
$definition = Join-Path $out 'selected-ucrt.def'
@'
LIBRARY ucrtbase.dll
EXPORTS
memcpy
memmove
memset
memcmp
strlen
strcmp
strncmp
wcslen
malloc
calloc
realloc
free
_errno
'@ | Set-Content -Encoding ascii $definition
$library = Join-Path $out 'selected-ucrt.lib'
$batch = Join-Path $out 'build.cmd'
$commands = @('@echo off', "call `"$vcvars`"", 'if errorlevel 1 exit /b 1',
    "lib /nologo /machine:x64 /def:`"$definition`" /out:`"$library`"", 'if errorlevel 1 exit /b 1')
$specs = @(
 @{ name='buffers'; case=1; exit=[uint32]0x34567891; stdout="FLEX_W5_BUFFERS_OK`n" },
 @{ name='heap'; case=2; exit=[uint32]0x34567892; stdout="FLEX_W5_HEAP_OK`n" },
 @{ name='integer'; case=3; exit=[uint32]0x34567893; stdout="FLEX_W5_INTEGER_OK`n" },
 @{ name='divide-zero'; case=4; exit=[uint32]3221225620; stdout='' },
 @{ name='access-fault'; case=5; exit=[uint32]3221225477; stdout='' },
 @{ name='illegal-instruction'; case=6; exit=[uint32]3221225501; stdout='' }
)
foreach ($spec in $specs) {
    $obj = Join-Path $out ($spec.name + '.obj')
    $exe = Join-Path $out ($spec.name + '.exe')
    $commands += "cl /nologo /W4 /WX /O1 /Oi- /Ob0 /GS- /Zl /DW5_CASE=$($spec.case) /c `"$source`" /Fo`"$obj`""
    $commands += 'if errorlevel 1 exit /b 1'
    $commands += "link /nologo /machine:x64 /entry:flex_entry /subsystem:console /nodefaultlib /fixed /dynamicbase:no /debug:none `"$obj`" `"$library`" kernel32.lib /out:`"$exe`""
    $commands += 'if errorlevel 1 exit /b 1'
}
$commands += 'exit /b 0'
$commands | Set-Content -Encoding ascii $batch
& cmd.exe /d /c $batch 2>&1 | Out-File (Join-Path $out 'build.log')
if ($LASTEXITCODE -ne 0) { Get-Content (Join-Path $out 'build.log'); throw 'W5 reference build failed' }
# Prevent crash dialogs in these intentionally faulting child processes.
Add-Type 'using System; using System.Runtime.InteropServices; public static class FlexW5ErrorMode { [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode); }'
$previous = [FlexW5ErrorMode]::SetErrorMode(0x8003)
$results = [ordered]@{}
$passed = $true
try {
    foreach ($spec in $specs) {
        $exe = Join-Path $out ($spec.name + '.exe')
        $start = [System.Diagnostics.ProcessStartInfo]::new($exe)
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::Start($start)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(10000)) { $process.Kill(); throw "W5 reference timeout: $($spec.name)" }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $code = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$process.ExitCode),0)
        $ok = $code -eq $spec.exit -and $stdout -ceq $spec.stdout -and $stderr -ceq ''
        $passed = $passed -and $ok
        $results[$spec.name] = [ordered]@{
            executable_sha256=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
            exit_code=$code; stdout=$stdout; stderr=$stderr; passed=$ok
        }
    }
} finally { [void][FlexW5ErrorMode]::SetErrorMode($previous) }
$receipt = [ordered]@{
 schema='compact-windows-w5-reference/v1'
 platform=[System.Runtime.InteropServices.RuntimeInformation]::OSDescription
 architecture=[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
 source_commit=$env:GITHUB_SHA
 source_sha256=(Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant()
 workloads=$results
 native_reference_passed=$passed
 native_kernel_qualified=$false
}
$receipt | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $out 'native-suite.json')
if (!$passed) { $receipt | ConvertTo-Json -Depth 6; throw 'W5 native reference mismatch' }
Write-Output 'All six Windows compiler/CRT references passed.'
