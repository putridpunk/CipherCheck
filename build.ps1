# Builds the Windows executables (ciphercheck.exe and ciphercheck-cli.exe) via build.py.
# For Linux/macOS run `python build.py` on that OS, or use the release workflow.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) { python -m venv .venv }
$py = @(".venv\Scripts\python.exe", ".venv\bin\python.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1

& $py -m pip install --quiet pyinstaller
& $py build.py
if ($LASTEXITCODE -ne 0) { throw "Build failed." }
