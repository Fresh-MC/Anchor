@echo off
REM ANCHOR Setup Script for Windows
REM ================================

echo ======================================================================
echo    ANCHOR - Real-Time Voice AI Agent Setup (Windows)
echo ======================================================================
echo.

REM Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found! Please install Python 3.9+ from python.org
    pause
    exit /b 1
)

echo [1/4] Creating virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

echo [3/4] Upgrading pip...
python -m pip install --upgrade pip setuptools wheel

echo [4/4] Installing dependencies from requirements_v2.txt...
pip install -r requirements_v2.txt
if %errorlevel% neq 0 (
    echo.
    echo WARNING: Some packages may have failed to install.
    echo.
    echo Common fixes:
    echo   - For PyAudio errors: conda install pyaudio
    echo   - For llama-cpp errors: pip install llama-cpp-python --no-cache-dir
    echo   - For TTS errors: pip install TTS --no-deps then pip install -r requirements_v2.txt
    echo.
)

echo.
echo ======================================================================
echo    Setup Complete!
echo ======================================================================
echo.
echo To run ANCHOR:
echo   1. Activate the environment: venv\Scripts\activate
echo   2. Run: python run_anchor.py
echo.
echo To test jailbreak protection:
echo   python test_jailbreak.py
echo.
pause
