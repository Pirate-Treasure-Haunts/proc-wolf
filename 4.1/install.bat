@echo off
echo ===================================
echo Proc-Wolf Installation
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

echo Installing Proc-Wolf Service...
echo.

:: 1. Stop the service if it's already running
echo Checking if service already exists...
sc query "ProcWolfService" >nul 2>&1
if %errorLevel% equ 0 (
    echo Found existing service, stopping it first...
    net stop "ProcWolfService" >nul 2>&1
    timeout /t 2 /nobreak >nul
)

:: 2. Remove existing service if it exists
sc query "ProcWolfService" >nul 2>&1
if %errorLevel% equ 0 (
    echo Removing existing service...
    "%~dp0ProcWolfService.exe" remove
    
    :: CHECK: Did the removal command fail? (Pywin32 service commands return non-zero on failure)
    if %errorLevel% neq 0 (
        echo ERROR: Failed to remove the existing service.
        echo Please check ProcWolfService.exe logs for details.
        pause
        exit /B 1
    )
    timeout /t 2 /nobreak >nul
)

:: 3. Install the service
echo Installing service...
"%~dp0ProcWolfService.exe" --startup auto install

:: CHECK: Did the installation command fail? (Crucial check here)
if %errorLevel% neq 0 (
    echo.
    echo ===================================
    echo Installation Failed
    echo ===================================
    echo.
    echo The Proc-Wolf service could not be installed.
    echo This often means a dependency is missing inside the executable (e.g., win32timezone).
    echo Check the console output or the log file for specific errors.
    pause
    exit /B 1
)

:: 4. Start the service
echo Starting Proc-Wolf Service...
net start "ProcWolfService"

:: Final Check: Check the error level of net start (0 is success)
if %errorLevel% equ 0 (
    echo.
    echo ===================================
    echo Installation successful!
    echo ===================================
    echo.
    echo The Proc-Wolf service is now running in the background.
    echo.
    echo To use the system tray monitor: Run ProcWolf.exe
    echo To use the CLI commands: Run ProcWolfCLI.exe
    echo.
    echo Log files are stored in:
    echo - Service logs: C:\ProgramData\proc-wolf\
    echo - Client logs: Same folder as the executable
    echo.
) else (
    echo.
    echo ===================================
    echo Service Start Failed
    echo ===================================
    echo.
    echo The service was installed, but failed to start.
    echo This usually means an exception occurred inside the service's Run() method.
    echo Check the Windows Event Log (Application) AND the service log file for errors.
    echo.
)

pause