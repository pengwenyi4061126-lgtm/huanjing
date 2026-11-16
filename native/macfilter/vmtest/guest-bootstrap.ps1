$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
$dst = 'C:\cacmac'
New-Item -ItemType Directory -Path $dst -Force | Out-Null
Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force
& (Join-Path $dst 'guest-stage2.ps1')
