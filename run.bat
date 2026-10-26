@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv" (
    echo [sv1] creating virtual environment...
    python -m venv .venv
    call ".venv\Scripts\activate.bat"
    python -m pip install --upgrade pip >nul
    python -m pip install -r requirements.txt
    python -m playwright install chromium
) else (
    call ".venv\Scripts\activate.bat"
)
python sv1.py %*
endlocal
