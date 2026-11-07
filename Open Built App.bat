@echo off
setlocal
cd /d "%~dp0"
if not exist "dist-demo\AI Traffic Control\AI Traffic Control.exe" (
  echo Build the standalone desktop app first by running "Build Windows App.ps1".
  pause
  exit /b 1
)
start "" "%~dp0dist-demo\AI Traffic Control\AI Traffic Control.exe"
