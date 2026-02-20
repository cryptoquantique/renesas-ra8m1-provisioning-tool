@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Crypto Broker Service - Uninstallation
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

REM Stop service if running
echo [1/3] Stopping service...
sc query CryptoBroker >nul 2>&1
if %errorLevel% == 0 (
    net stop CryptoBroker >nul 2>&1
    timeout /t 2 >nul
)

REM Remove service
echo [2/3] Removing service...
python -m security.broker.service.windows_service remove
if %errorLevel% neq 0 (
    echo   Trying alternative removal method...
    sc delete CryptoBroker >nul 2>&1
)

REM Ask about removing data
echo [3/3] Cleanup...
set "DATA_DIR=%PROGRAMDATA%\CryptoBroker"
if exist "%DATA_DIR%" (
    echo.
    set /p "REMOVE_DATA=Remove configuration and logs? [y/N]: "
    if /i "!REMOVE_DATA!"=="y" (
        rmdir /s /q "%DATA_DIR%"
        echo   Data directory removed
    ) else (
        echo   Data directory preserved at: %DATA_DIR%
    )
)

echo.
echo ============================================
echo Uninstallation Complete!
echo ============================================
echo.

pause
