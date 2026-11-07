@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  where py >nul 2>nul
  if errorlevel 1 goto no_python
  set "PYTHON_CMD=py -3"
) else (
  set "PYTHON_CMD=python"
)
if not exist ".venv\Scripts\python.exe" (
  call %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto failed
)
call ".venv\Scripts\python.exe" --version
if errorlevel 1 goto failed
call ".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 goto old_python
call ".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
call ".venv\Scripts\python.exe" -m traffic_control
if errorlevel 1 goto failed
exit /b 0
:no_python
  echo Python 3.10 or newer is required. Install Python from python.org and enable the Python launcher.
  pause
  exit /b 1
:old_python
echo Python 3.10 or newer is required. Install a current Python release and try again.
pause
exit /b 1
:failed
echo AI Traffic Control could not start. Review the error above. If installation failed, check your Python installation and network connection.
pause
exit /b 1
