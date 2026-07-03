[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$assetDirectory = Join-Path $root "src\UsbSentinel.Desktop\Assets"
$iconPath = Join-Path $assetDirectory "UsbSentinel.ico"
New-Item -ItemType Directory -Path $assetDirectory -Force | Out-Null

$size = 256
$bitmap = New-Object System.Drawing.Bitmap($size, $size)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::FromArgb(12, 18, 28))

$shield = New-Object System.Drawing.Drawing2D.GraphicsPath
$shield.AddPolygon([System.Drawing.Point[]]@(
    [System.Drawing.Point]::new(128, 20),
    [System.Drawing.Point]::new(218, 54),
    [System.Drawing.Point]::new(210, 142),
    [System.Drawing.Point]::new(178, 198),
    [System.Drawing.Point]::new(128, 232),
    [System.Drawing.Point]::new(78, 198),
    [System.Drawing.Point]::new(46, 142),
    [System.Drawing.Point]::new(38, 54)
))
$shieldBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    [System.Drawing.Point]::new(40, 30),
    [System.Drawing.Point]::new(215, 225),
    [System.Drawing.Color]::FromArgb(0, 222, 255),
    [System.Drawing.Color]::FromArgb(0, 255, 143))
$graphics.FillPath($shieldBrush, $shield)

$innerShield = New-Object System.Drawing.Drawing2D.GraphicsPath
$innerShield.AddPolygon([System.Drawing.Point[]]@(
    [System.Drawing.Point]::new(128, 40),
    [System.Drawing.Point]::new(197, 66),
    [System.Drawing.Point]::new(190, 136),
    [System.Drawing.Point]::new(164, 181),
    [System.Drawing.Point]::new(128, 207),
    [System.Drawing.Point]::new(92, 181),
    [System.Drawing.Point]::new(66, 136),
    [System.Drawing.Point]::new(59, 66)
))
$graphics.FillPath((New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(16, 27, 39))), $innerShield)

$white = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 13)
$white.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$white.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$graphics.DrawLine($white, 128, 82, 128, 166)
$graphics.DrawLine($white, 128, 117, 96, 117)
$graphics.DrawLine($white, 96, 117, 96, 143)
$graphics.DrawLine($white, 128, 137, 158, 107)
$graphics.FillEllipse([System.Drawing.Brushes]::White, 86, 137, 20, 20)
$graphics.FillEllipse([System.Drawing.Brushes]::White, 151, 94, 20, 20)
$graphics.FillPolygon([System.Drawing.Brushes]::White, [System.Drawing.Point[]]@(
    [System.Drawing.Point]::new(128, 65),
    [System.Drawing.Point]::new(114, 88),
    [System.Drawing.Point]::new(142, 88)
))

$pngStream = New-Object System.IO.MemoryStream
$bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $pngStream.ToArray()
$file = [System.IO.File]::Create($iconPath)
$writer = New-Object System.IO.BinaryWriter($file)
$writer.Write([UInt16]0)
$writer.Write([UInt16]1)
$writer.Write([UInt16]1)
$writer.Write([Byte]0)
$writer.Write([Byte]0)
$writer.Write([Byte]0)
$writer.Write([Byte]0)
$writer.Write([UInt16]1)
$writer.Write([UInt16]32)
$writer.Write([UInt32]$pngBytes.Length)
$writer.Write([UInt32]22)
$writer.Write($pngBytes)
$writer.Dispose()
$pngStream.Dispose()
$white.Dispose()
$innerShield.Dispose()
$shieldBrush.Dispose()
$shield.Dispose()
$graphics.Dispose()
$bitmap.Dispose()

Write-Host "Created $iconPath" -ForegroundColor Green
