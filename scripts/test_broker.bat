@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Crypto Broker - Connection Test
echo ============================================
echo.

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."
cd /d "%PROJECT_DIR%"

REM Check service status
echo [1/4] Checking service status...
sc query CryptoBroker >nul 2>&1
if %errorLevel% neq 0 (
    echo   Service: NOT INSTALLED
    echo.
    echo   Install with: scripts\install_broker_service.bat
    echo.
    goto :done
)

sc query CryptoBroker 2>nul | find "RUNNING" >nul
if %errorLevel% == 0 (
    echo   Service: RUNNING
) else (
    echo   Service: STOPPED
    echo.
    echo   Start with: net start CryptoBroker
    echo.
    goto :done
)

REM Check named pipe
echo [2/4] Checking named pipe...
if exist "\\.\pipe\crypto_broker" (
    echo   Pipe: EXISTS
) else (
    echo   Pipe: NOT FOUND
    echo.
    echo   Service may not have started correctly.
    echo   Check logs at: %PROGRAMDATA%\CryptoBroker\logs\broker.log
    echo.
    goto :done
)

REM Ping broker
echo [3/4] Pinging broker...
python -m cli broker ping >nul 2>&1
if %errorLevel% == 0 (
    echo   Ping: SUCCESS
) else (
    echo   Ping: FAILED
    echo.
    echo   Run 'python -m cli broker ping' for details
    goto :done
)

REM Check broker status
echo [4/4] Getting broker status...
echo.
python -m cli broker status

:done
echo.
pause
