# SPDX-License-Identifier: GPL-3.0-only
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
& (Join-Path $PSScriptRoot 'compact_windows_w5_reference.ps1')
& (Join-Path $PSScriptRoot 'compact_windows_w4_reference.ps1')
& (Join-Path $PSScriptRoot 'compact_windows_w3_reference.ps1')
$out=Join-Path $root 'artifacts/compact-windows/w6-fixtures'
New-Item -ItemType Directory -Force $out | Out-Null
$base=Join-Path $root 'artifacts/compact-windows'
foreach($name in @('buffers','heap','integer','divide-zero','access-fault','illegal-instruction')) {
 Copy-Item (Join-Path $base "w5-reference/$name.exe") (Join-Path $out "$name.exe")
}
Copy-Item (Join-Path $base 'w5-reference/native-suite.json') (Join-Path $out 'w5.json')
Copy-Item (Join-Path $base 'w4-reference/reference.exe') (Join-Path $out 'file.exe')
Copy-Item (Join-Path $base 'w4-reference/native-reference.json') (Join-Path $out 'w4.json')
Copy-Item (Join-Path $base 'w3-reference/reference.exe') (Join-Path $out 'api.exe')
Copy-Item (Join-Path $base 'w3-reference/native-reference.json') (Join-Path $out 'w3.json')
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$install=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars=Join-Path $install 'VC/Auxiliary/Build/vcvars64.bat'
$library=Join-Path $base 'w5-reference/selected-ucrt.lib'
$source=Join-Path $root 'tests/fixtures/windows_w6_limits.c'
$commands=@('@echo off',"call `"$vcvars`"",'if errorlevel 1 exit /b 1')
$specs=@('heap-limit','io-limit','handle-limit','ramfs-io')
for($i=0;$i -lt $specs.Count;$i++) {
 $name=$specs[$i];$obj=Join-Path $out "$name.obj";$exe=Join-Path $out "$name.exe"
 $commands+="cl /nologo /W4 /WX /O1 /Oi- /Ob0 /GS- /Zl /DW6_CASE=$($i+1) /c `"$source`" /Fo`"$obj`""
 $commands+='if errorlevel 1 exit /b 1'
 $commands+="link /nologo /machine:x64 /entry:flex_entry /subsystem:console /nodefaultlib /fixed /dynamicbase:no /debug:none `"$obj`" `"$library`" kernel32.lib /out:`"$exe`""
 $commands+='if errorlevel 1 exit /b 1'
}
$commands+='exit /b 0';$batch=Join-Path $out 'build.cmd';$commands|Set-Content -Encoding ascii $batch
& cmd.exe /d /c $batch 2>&1 | Out-File (Join-Path $out 'limits-build.log')
if($LASTEXITCODE -ne 0){Get-Content (Join-Path $out 'limits-build.log');throw 'Limit fixture build failed'}
$hashes=[ordered]@{};foreach($name in $specs){$hashes[$name]=(Get-FileHash (Join-Path $out "$name.exe") -Algorithm SHA256).Hash.ToLowerInvariant()}
[ordered]@{schema='compact-windows-w6-fixtures/v1';source_commit=$env:GITHUB_SHA;source_sha256=(Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant();compiled_only=$true;images=$hashes} | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $out 'limits.json')
