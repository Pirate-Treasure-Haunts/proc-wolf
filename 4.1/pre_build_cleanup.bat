@echo off
echo ===================================
echo Proc-Wolf Pre-Build Cleanup
echo ===================================
echo.
echo Stopping any running instances before build...
echo.

:: Stop the service if it exists
echo Stopping service...
net stop ProcWolfService 2>nul

:: Give it a moment to stop
timeout /t 2 /nobreak >nul

:: Force kill all proc-wolf processes
echo Killing any remaining processes...
taskkill /F /IM "ProcWolfService.exe" 2>nul
taskkill /F /IM "ProcWolf.exe" 2>nul
taskkill /F /IM "ProcWolfCLI.exe" 2>nul
taskkill /F /IM "proc_wolf.exe" 2>nul

:: Clean up any lock files
echo Cleaning up...
del /F /Q ".\dist\*.exe.lock" 2>nul

echo.
echo ===================================
echo Cleanup complete!
echo ===================================
echo.
echo It's now safe to run: python build_exe.py
echo.
pause
