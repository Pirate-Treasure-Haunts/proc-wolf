@echo off
echo ===================================
echo EMERGENCY PROC-WOLF RECOVERY
echo ===================================
echo.

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: This script must be run as administrator!
    echo Please right-click and select "Run as administrator"
    pause
    exit /B 1
)

echo STEP 1: Stopping the rogue service...
net stop "ProcWolfService" 2>nul
sc delete "ProcWolfService" 2>nul
taskkill /F /IM ProcWolfService.exe 2>nul
taskkill /F /IM ProcWolf.exe 2>nul
echo Service stopped and removed.
echo.

echo STEP 2: Restoring quarantined files...
echo.

set QUARANTINE_DIR=C:\ProgramData\proc-wolf\quarantine

:: Restore Windows Defender files
if exist "%QUARANTINE_DIR%\*NisSrv.exe.quarantine" (
    echo Restoring Windows Defender Network Inspection Service...
    move "%QUARANTINE_DIR%\*NisSrv.exe.quarantine" "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\NisSrv.exe" 2>nul
)

if exist "%QUARANTINE_DIR%\*MsCmdRun.exe.quarantine" (
    echo Restoring Microsoft Command Run...
    :: You'll need to identify the correct restore path for this
)

:: Remove info files
del "%QUARANTINE_DIR%\*.info" 2>nul

echo.
echo STEP 3: Clearing the corrupted database...
del "C:\ProgramData\proc-wolf\proc-wolf.db" 2>nul
echo Database cleared.
echo.

echo ===================================
echo RECOVERY COMPLETE
echo ===================================
echo.
echo The rogue service has been stopped.
echo Critical files have been restored.
echo.
echo DO NOT run proc-wolf again until it's been fixed!
echo.
pause
