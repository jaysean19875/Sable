# Build the standalone Windows executable with PyInstaller.
# Output: dist\ProjectOSINT.exe (one-file, windowed, portable).

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path "$root\assets\projectosint.ico")) {
    & "$root\.venv\Scripts\python.exe" "$root\assets\make_icon.py"
}

& "$root\.venv\Scripts\python.exe" -m PyInstaller `
    --noconfirm --clean --onefile --windowed `
    --name ProjectOSINT `
    --icon "$root\assets\projectosint.ico" `
    --exclude-module PySide6.QtWebEngineCore `
    --exclude-module PySide6.QtWebEngineWidgets `
    --exclude-module PySide6.QtWebChannel `
    --exclude-module PySide6.QtQml `
    --exclude-module PySide6.QtQuick `
    --exclude-module PySide6.QtMultimedia `
    --exclude-module PySide6.QtCharts `
    --exclude-module PySide6.Qt3DCore `
    --exclude-module PySide6.QtDataVisualization `
    --exclude-module PySide6.QtTest `
    --exclude-module PySide6.QtPdf `
    --exclude-module PySide6.QtSql `
    --exclude-module PySide6.QtSvg `
    "$root\ProjectOSINT.py"

Copy-Item "$root\config.yaml" "$root\dist\config.yaml" -Force
Copy-Item "$root\.env.example" "$root\dist\.env.example" -Force

Write-Host ""
Write-Host "Built: dist\ProjectOSINT.exe"
$size = [math]::Round((Get-Item "$root\dist\ProjectOSINT.exe").Length / 1MB, 1)
Write-Host "Size:  $size MB"
