#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$ServiceDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) "artifacts\service")
)

$ErrorActionPreference = "Stop"
$serviceName = "UsbSentinelPro"
$executable = Join-Path $ServiceDirectory "UsbSentinel.Service.exe"
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Service executable not found: $executable. Run scripts\build.ps1 first."
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

sc.exe create $serviceName binPath= "`"$executable`"" start= auto obj= LocalSystem `
    DisplayName= "USB Sentinel Pro Service" | Out-Null
sc.exe description $serviceName "Controls removable USB storage and Microsoft Defender scanning." | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null
Start-Service -Name $serviceName
Write-Host "USB Sentinel Pro Service installed and running." -ForegroundColor Green
