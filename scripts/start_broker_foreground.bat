@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Crypto Broker - Foreground Mode (Debug)
echo ============================================
echo.
echo This starts the broker in foreground mode for debugging.
echo Press Ctrl+C to stop.
echo.

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."
cd /d "%PROJECT_DIR%"

REM Check if service is running
sc query CryptoBroker 2>nul | find "RUNNING" >nul
if %errorLevel% == 0 (
    echo WARNING: CryptoBroker service is already running!
    echo Stop it first with: net stop CryptoBroker
    echo.
    pause
    exit /b 1
)

REM Check AWS credentials
if not defined AWS_ACCESS_KEY_ID (
    echo WARNING: AWS_ACCESS_KEY_ID not set
    echo The broker may fail to connect to AWS KMS
    echo.
)

echo Starting broker on \\.\pipe\crypto_broker ...
echo.

REM Start broker in foreground
python -m cli broker start --foreground

echo.
echo Broker stopped.
pause
