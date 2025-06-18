@echo off
echo Starting ReconToolKit...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://python.org
    pause
    exit /b 1
)

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

REM Create data directory if it doesn't exist
if not exist "data" mkdir data

REM Launch the application
echo Launching ReconToolKit GUI...
python main.py

REM If the application exits with an error, show message
if errorlevel 1 (
    echo.
    echo ReconToolKit exited with an error.
    echo Check the logs directory for more information.
    pause
)
