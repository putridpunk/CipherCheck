# Builds a single-file Windows executable: dist\ciphercheck.exe
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) { python -m venv .venv }
$py = @(".venv\Scripts\python.exe", ".venv\bin\python.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1

& $py -m pip install --quiet pyinstaller
& $py -m unittest discover -s tests -t .
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }

& $py -m PyInstaller --noconfirm --clean --onefile --name ciphercheck `
    --add-data "data$([IO.Path]::PathSeparator)data" ciphercheck.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

Write-Host "Built: $PSScriptRoot\dist\ciphercheck.exe"
