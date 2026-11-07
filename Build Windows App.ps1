$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $python -m pip install -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) { throw "Could not install build requirements." }
& $python -m PyInstaller --noconfirm --clean --windowed --name "AI Traffic Control" `
    --icon assets\ai-traffic-control.ico --distpath dist-demo --workpath build-demo `
    --collect-all keyring --collect-all uvicorn --collect-all fastapi --collect-all regex `
    --hidden-import keyring.backends.Windows --hidden-import win32ctypes `
    run_app.py
if ($LASTEXITCODE -ne 0) { throw "Windows app build failed." }
Write-Host "Built app: $PSScriptRoot\dist-demo\AI Traffic Control\AI Traffic Control.exe"
