# Builds two Windows executables in the project root:
#   ciphercheck.exe      - the desktop app (Matrix-themed UI, no console window)
#   ciphercheck-cli.exe  - the terminal version
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) { python -m venv .venv }
$py = @(".venv\Scripts\python.exe", ".venv\bin\python.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1

& $py -m pip install --quiet pyinstaller
& $py -m unittest discover -s tests -t .
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }

$data = "data$([IO.Path]::PathSeparator)data"
& $py -m PyInstaller --noconfirm --clean --onefile --windowed --name ciphercheck --add-data $data ciphercheck.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller (app) failed." }
& $py -m PyInstaller --noconfirm --onefile --name ciphercheck-cli --add-data $data ciphercheck_cli.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller (cli) failed." }

Copy-Item "dist\ciphercheck.exe", "dist\ciphercheck-cli.exe" "." -Force
Write-Host "Built: $PSScriptRoot\ciphercheck.exe and ciphercheck-cli.exe"
