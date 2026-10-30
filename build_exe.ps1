# Build the standalone Windows bundles with PyInstaller.
#
#   .\build_exe.ps1              -> portable folder + zip  (recommended: fewer AV heuristics)
#   .\build_exe.ps1 -OneFile     -> single-file exe
#
# Output:
#   dist-portable\ProjectOSINT-portable\             the app (exe + _internal\)
#   dist-portable\ProjectOSINT-0.1.0-portable-win64.zip
#   dist\ProjectOSINT.exe                            (only with -OneFile)

param([switch]$OneFile)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path "$root\assets\projectosint.ico")) {
    & "$root\.venv\Scripts\python.exe" "$root\assets\make_icon.py"
}

# Dead weight for a runtime bundle. Two of these are surprising but real:
#   mypy -> pulled in by PyInstaller's pydantic hook (collect_submodules('pydantic'))
#   PIL  -> pulled in by reportlab's optional imaging support
# Both are excluded here; the app never imports them at runtime.
$excludes = @(
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebChannel",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtMultimedia", "PySide6.QtCharts",
    "PySide6.Qt3DCore", "PySide6.QtDataVisualization", "PySide6.QtTest",
    "PySide6.QtPdf", "PySide6.QtSql", "PySide6.QtSvg",
    "mypy", "PIL", "tkinter", "pydantic.mypy", "pytest", "respx"
)
$excludeArgs = foreach ($module in $excludes) { "--exclude-module"; $module }

if ($OneFile) {
    & "$root\.venv\Scripts\python.exe" -m PyInstaller `
        --noconfirm --clean --onefile --windowed `
        --name ProjectOSINT `
        --icon "$root\assets\projectosint.ico" `
        --version-file "$root\assets\version_info.txt" `
        @excludeArgs "$root\ProjectOSINT.py"
    Copy-Item "$root\config.yaml" "$root\dist\config.yaml" -Force
    Copy-Item "$root\.env.example" "$root\dist\.env.example" -Force
    Write-Host "Built: dist\ProjectOSINT.exe"
    return
}

& "$root\.venv\Scripts\python.exe" -m PyInstaller `
    --noconfirm --clean --onedir --windowed `
    --name ProjectOSINT-portable `
    --distpath "$root\dist-portable" --workpath "$root\build-portable" `
    --icon "$root\assets\projectosint.ico" `
    --version-file "$root\assets\version_info.txt" `
    @excludeArgs "$root\ProjectOSINT.py"

$folder = "$root\dist-portable\ProjectOSINT-portable"
Copy-Item "$root\config.yaml" "$folder\config.yaml" -Force
Copy-Item "$root\.env.example" "$folder\.env.example" -Force
Compress-Archive -Path "$folder\*" -DestinationPath "$root\dist-portable\ProjectOSINT-0.1.0-portable-win64.zip" -Force

Write-Host ""
Write-Host "Built: dist-portable\ProjectOSINT-portable\"
Write-Host "Zip:   dist-portable\ProjectOSINT-0.1.0-portable-win64.zip"
