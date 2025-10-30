@echo off
:: Proc-Wolf Service Control Script
:: Provides better control over the service

echo ===================================
echo Proc-Wolf Service Control
echo ===================================
echo.
echo 1. STATUS - Check service status
echo 2. START  - Start the service
echo 3. STOP   - Stop the service
echo 4. RESTART - Restart the service
echo 5. KILL   - Force kill all instances
echo 6. CLEAN  - Remove service completely
echo 7. DEBUG  - Run in debug mode
echo.
set /p choice="Select option (1-7): "

if "%choice%"=="1" goto STATUS
if "%choice%"=="2" goto START
if "%choice%"=="3" goto STOP
if "%choice%"=="4" goto RESTART
if "%choice%"=="5" goto KILL
if "%choice%"=="6" goto CLEAN
if "%choice%"=="7" goto DEBUG
echo Invalid choice!
goto END

:STATUS
echo.
echo Checking service status...
sc query ProcWolfService
echo.
echo Checking for running processes...
tasklist | findstr -i "procwolf"
goto END

:START
echo.
echo Starting service...
net start ProcWolfService
goto END

:STOP
echo.
echo Stopping service gracefully...
net stop ProcWolfService
timeout /t 3 /nobreak >nul
:: If still running after 3 seconds, force kill
tasklist | findstr -i "ProcWolfService" >nul
if %errorlevel%==0 (
    echo Service didn't stop gracefully, forcing...
    taskkill /F /IM "ProcWolfService.exe"
)
goto END

:RESTART
echo.
echo Restarting service...
net stop ProcWolfService
timeout /t 2 /nobreak >nul
taskkill /F /IM "ProcWolfService.exe" 2>nul
net start ProcWolfService
goto END

:KILL
echo.
echo Force killing all proc-wolf instances...
taskkill /F /IM "ProcWolfService.exe" 2>nul
taskkill /F /IM "ProcWolf.exe" 2>nul
taskkill /F /IM "proc_wolf.exe" 2>nul
echo All instances killed.
goto END

:CLEAN
echo.
echo Completely removing service...
net stop ProcWolfService 2>nul
timeout /t 2 /nobreak >nul
taskkill /F /IM "ProcWolfService.exe" 2>nul
sc delete ProcWolfService
echo Service removed.
goto END

:DEBUG
echo.
echo Running in debug mode...
echo Press Ctrl+C to stop (may need to use option 5 to fully kill)
"%~dp0ProcWolfService.exe" debug
goto END

:END
echo.
pause
