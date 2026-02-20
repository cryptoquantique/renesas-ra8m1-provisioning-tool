@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Crypto Broker Service - Windows Installation
echo ============================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required.
    echo Please right-click and "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."
cd /d "%PROJECT_DIR%"

echo Project directory: %PROJECT_DIR%
echo.

REM Check Python
echo [1/7] Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python not found in PATH
    echo Please install Python 3.10+ and add to PATH
    pause
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo   Python version: %PYTHON_VERSION%

REM Check pywin32
echo [2/7] Checking pywin32...
python -c "import win32serviceutil" >nul 2>&1
if %errorLevel% neq 0 (
    echo   Installing pywin32...
    pip install pywin32
    if %errorLevel% neq 0 (
        echo ERROR: Failed to install pywin32
        pause
        exit /b 1
    )
    echo   Running pywin32 post-install...
    python -m pywin32_postinstall -install
)
echo   pywin32 OK

REM Create data directory
echo [3/7] Creating data directories...
set "DATA_DIR=%PROGRAMDATA%\CryptoBroker"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\logs" mkdir "%DATA_DIR%\logs"
echo   %DATA_DIR%

REM Copy configuration files
echo [4/7] Copying configuration files...
if exist "%PROJECT_DIR%\broker_config.json" (
    copy /Y "%PROJECT_DIR%\broker_config.json" "%DATA_DIR%\broker_config.json" >nul
    echo   broker_config.json copied
)
if exist "%PROJECT_DIR%\broker_policies_windows.json" (
    copy /Y "%PROJECT_DIR%\broker_policies_windows.json" "%DATA_DIR%\broker_policies.json" >nul
    echo   broker_policies.json copied
)

REM Install the service
echo [5/7] Installing Windows service...
python -m security.broker.service.windows_service install
if %errorLevel% neq 0 (
    echo ERROR: Failed to install service
    pause
    exit /b 1
)

REM Configure service
echo [6/7] Configuring service...
sc config CryptoBroker start= auto >nul 2>&1
sc description CryptoBroker "PKCS#11 broker for AWS KMS cryptographic operations. Required for RA8M1 provisioning tool." >nul 2>&1
sc failure CryptoBroker reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1

REM Check AWS credentials
echo [7/7] Checking AWS credentials...
set "AWS_OK=0"
if defined AWS_ACCESS_KEY_ID (
    echo   AWS_ACCESS_KEY_ID: set
    set "AWS_OK=1"
) else (
    echo   AWS_ACCESS_KEY_ID: not set
)

echo.
echo ============================================
echo Installation Complete!
echo ============================================
echo.
echo Service Name: CryptoBroker
echo Pipe Name: \\.\pipe\crypto_broker
echo Config: %DATA_DIR%\broker_config.json
echo Policies: %DATA_DIR%\broker_policies.json
echo Logs: %DATA_DIR%\logs\broker.log
echo.

if "%AWS_OK%"=="0" (
    echo WARNING: AWS credentials not found in environment.
    echo.
    echo Before starting the service, set AWS credentials:
    echo   setx /M AWS_ACCESS_KEY_ID "your_access_key"
    echo   setx /M AWS_SECRET_ACCESS_KEY "your_secret_key"
    echo   setx /M AWS_DEFAULT_REGION "eu-central-1"
    echo.
)

echo To start the service:
echo   net start CryptoBroker
echo.
echo To check status:
echo   sc query CryptoBroker
echo.
echo To test the broker:
echo   python -m cli broker ping
echo.

pause
