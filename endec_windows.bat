@echo off
cd /d "%~dp0"
echo Starting Endec...

:: Check if venv exists, if not create it
if not exist venv (
    echo Virtual environment not found. Creating...
    python -m venv venv
    call venv\Scripts\activate
    echo Installing dependencies...
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate
)

.\venv\Scripts\python endec.py
pause
