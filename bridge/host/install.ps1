# Installs the pdf-sign native messaging host for Chrome and Edge (per-user).
#
# Usage:
#   1. Load bridge/extension as an unpacked extension (chrome://extensions or
#      edge://extensions, Developer mode -> "Load unpacked") and copy its ID.
#   2. .\install.ps1 -ExtensionId <the-extension-id>
param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId
)

$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:LOCALAPPDATA 'pdf-sign-bridge'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$exePath = Join-Path $installDir 'pdfsign-bridge.exe'
Write-Host "Building $exePath ..."
Push-Location $PSScriptRoot
try {
    go build -o $exePath .
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
} finally {
    Pop-Location
}

$manifestPath = Join-Path $installDir 'com.pdfsign.bridge.json'
$manifestJson = @{
    name            = 'com.pdfsign.bridge'
    description     = 'pdf-sign smart card bridge'
    path            = $exePath
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json
# UTF-8 without BOM: Windows PowerShell 5.1's `Set-Content -Encoding UTF8`
# writes a BOM, which Chrome rejects when parsing the host manifest.
[System.IO.File]::WriteAllText($manifestPath, $manifestJson)

$registryRoots = @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts'
)
foreach ($root in $registryRoots) {
    $key = "$root\com.pdfsign.bridge"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name '(Default)' -Value $manifestPath
    Write-Host "Registered $key"
}

Write-Host ''
Write-Host 'Done. Reload the extension, then open http://127.0.0.1:8080 -'
Write-Host 'the banner should report the smart card bridge as connected.'
Write-Host "Debug the host directly with: & '$exePath' -cli list"
