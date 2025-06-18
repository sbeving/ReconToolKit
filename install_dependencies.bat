@echo off
echo Installing ReconToolKit Dependencies...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://python.org
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Found Python %PYTHON_VERSION%

REM Install dependencies
echo.
echo Installing required packages...
pip install PyQt5==5.15.9
if errorlevel 1 (
    echo Error installing PyQt5
    pause
    exit /b 1
)

pip install requests==2.31.0
if errorlevel 1 (
    echo Error installing requests
    pause
    exit /b 1
)

pip install dnspython==2.4.2
if errorlevel 1 (
    echo Error installing dnspython
    pause
    exit /b 1
)

pip install python-whois==0.8.0
if errorlevel 1 (
    echo Error installing python-whois
    pause
    exit /b 1
)

pip install beautifulsoup4==4.12.2
if errorlevel 1 (
    echo Error installing beautifulsoup4
    pause
    exit /b 1
)

pip install pycryptodome==3.18.0
if errorlevel 1 (
    echo Error installing pycryptodome
    pause
    exit /b 1
)

pip install reportlab==4.0.4
if errorlevel 1 (
    echo Error installing reportlab
    pause
    exit /b 1
)

pip install jinja2==3.1.2
if errorlevel 1 (
    echo Error installing jinja2
    pause
    exit /b 1
)

pip install python-nmap==0.7.1
if errorlevel 1 (
    echo Error installing python-nmap
    pause
    exit /b 1
)

pip install aiohttp==3.9.1
if errorlevel 1 (
    echo Error installing aiohttp
    pause
    exit /b 1
)

pip install asyncio==3.4.3
if errorlevel 1 (
    echo Error installing asyncio
    pause
    exit /b 1
)

pip install aiodns==3.1.1
if errorlevel 1 (
    echo Error installing aiodns
    pause
    exit /b 1
)



pip install urllib3==2.0.7
if errorlevel 1 (
    echo Error installing urllib3
    pause
    exit /b 1
)

echo.
echo ================================
echo Installation completed successfully!
echo ================================
echo.
echo You can now run ReconToolKit with:
echo python main.py
echo.
pause
