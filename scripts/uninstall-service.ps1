#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$serviceName = "UsbSentinelPro"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
}
Write-Host "USB Sentinel Pro Service removed." -ForegroundColor Green
