[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$artifacts = Join-Path $root "artifacts"
$env:DOTNET_CLI_HOME = Join-Path $root ".dotnet-home"
$env:NUGET_PACKAGES = Join-Path $root ".nuget\packages"
$nugetConfig = Join-Path $root "NuGet.Config"

& (Join-Path $PSScriptRoot "create-icon.ps1")

function Invoke-DotNet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet command failed with exit code $LASTEXITCODE"
    }
}

Invoke-DotNet restore (Join-Path $root "USB Sentinel Pro.sln") --configfile $nugetConfig
Invoke-DotNet test (Join-Path $root "tests\UsbSentinel.Tests\UsbSentinel.Tests.csproj") -c $Configuration --no-restore
Invoke-DotNet publish (Join-Path $root "src\UsbSentinel.Service\UsbSentinel.Service.csproj") `
    -c $Configuration --self-contained true -o (Join-Path $artifacts "service")
Invoke-DotNet publish (Join-Path $root "src\UsbSentinel.Desktop\UsbSentinel.Desktop.csproj") `
    -c $Configuration --self-contained true -o (Join-Path $artifacts "desktop")
Invoke-DotNet restore (Join-Path $root "installer\UsbSentinel.Installer.wixproj") --configfile $nugetConfig
Invoke-DotNet build (Join-Path $root "installer\UsbSentinel.Installer.wixproj") `
    -c $Configuration -o (Join-Path $artifacts "installer")

Write-Host "Build complete: $artifacts" -ForegroundColor Green
