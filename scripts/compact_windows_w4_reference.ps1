# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root 'artifacts/compact-windows/w4-reference'
New-Item -ItemType Directory -Force $out | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$install) { throw 'MSVC x64 installation missing' }
$vcvars = Join-Path $install 'VC/Auxiliary/Build/vcvars64.bat'
$source = Join-Path $root 'tests/fixtures/windows_w4_reference.c'
$obj = Join-Path $out 'reference.obj'
$exe = Join-Path $out 'reference.exe'
$batch = Join-Path $out 'build.cmd'
@"
@echo off
call "$vcvars"
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O1 /GS- /Zl /c "$source" /Fo"$obj"
if errorlevel 1 exit /b 1
link /nologo /machine:x64 /entry:flex_entry /subsystem:console /nodefaultlib /fixed /dynamicbase:no /debug:none "$obj" kernel32.lib /out:"$exe"
exit /b %errorlevel%
"@ | Set-Content -Encoding ascii $batch
& cmd.exe /d /c $batch 2>&1 | Out-File (Join-Path $out 'build.log')
if ($LASTEXITCODE -ne 0) { Get-Content (Join-Path $out 'build.log'); throw 'Reference build failed' }
$start = [System.Diagnostics.ProcessStartInfo]::new($exe)
$start.UseShellExecute = $false
$work = Join-Path $out 'namespace-root'
New-Item -ItemType Directory -Force $work | Out-Null
$start.WorkingDirectory = $work
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [System.Diagnostics.Process]::Start($start)
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
if (!$process.WaitForExit(10000)) { $process.Kill(); throw 'Reference timed out' }
$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()
$passed = $process.ExitCode -eq 591751049 -and $stdout -ceq "FLEX_WINDOWS_W4_OK`n" -and $stderr -ceq ''
[System.IO.File]::WriteAllText((Join-Path $out 'stdout.txt'), $stdout)
[System.IO.File]::WriteAllText((Join-Path $out 'stderr.txt'), $stderr)
$file = Join-Path $work 'payload.bin'
$expected = [System.Text.Encoding]::ASCII.GetBytes("FLEX_WINDOWS_W4_FILE_OK`n") + [byte[]]@(0,0,0,33)
$bytes = if (Test-Path $file) { [System.IO.File]::ReadAllBytes($file) } else { [byte[]]@() }
$filePassed = ([Convert]::ToBase64String([byte[]]$expected) -ceq [Convert]::ToBase64String([byte[]]$bytes))
$passed = $passed -and $filePassed
$receipt = [ordered]@{
 schema = 'compact-windows-w4-reference/v1'
 platform = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
 architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
 source_commit = $env:GITHUB_SHA
 source_sha256 = (Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant()
 executable_sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
 file_sha256 = if (Test-Path $file) { (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
 exit_code = $process.ExitCode
 stdout = $stdout
 stderr = $stderr
 native_reference_passed = $passed
 windows_execution_qualified = $false
 evidence_scope = 'Windows host reference only; no Flex execution'
}
$receipt | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $out 'native-reference.json')
if (!$passed) { throw 'Native reference output/exit mismatch' }
Write-Output 'Windows file reference passed; compare identical PE and persistent bytes with hosted Flex namespace next.'
