[CmdletBinding()]
param([Parameter(Mandatory)][string]$CertificateBase64,
      [Parameter(Mandatory)][string]$CertificatePassword)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$certificatePath = Join-Path $env:RUNNER_TEMP "usb-sentinel-signing.pfx"
try {
    [IO.File]::WriteAllBytes($certificatePath, [Convert]::FromBase64String($CertificateBase64))
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -Recurse |
        Where-Object FullName -Match '\\x64\\signtool\.exe$' | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "Windows SDK signtool.exe was not found." }
    $executables = @(
        (Join-Path $root "artifacts\service\UsbSentinel.Service.exe"),
        (Join-Path $root "artifacts\desktop\UsbSentinel.Desktop.exe"))
    foreach ($file in $executables) {
        & $signtool.FullName sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f $certificatePath /p $CertificatePassword $file
        if ($LASTEXITCODE -ne 0) { throw "Signing failed for $file" }
    }
    & dotnet build (Join-Path $root "installer\UsbSentinel.Installer.wixproj") -c Release -o (Join-Path $root "artifacts\installer")
    if ($LASTEXITCODE -ne 0) { throw "Rebuilding the installer with signed executables failed." }
    $installer = Join-Path $root "artifacts\installer\USB-Sentinel-Pro-Setup.msi"
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f $certificatePath /p $CertificatePassword $installer
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $installer" }
}
finally {
    Remove-Item -LiteralPath $certificatePath -Force -ErrorAction SilentlyContinue
}
