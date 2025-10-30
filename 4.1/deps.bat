@echo off
echo ====================================================
echo Proc-Wolf Dependency Installer
echo ====================================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as administrator!
    echo Please right-click on the script and select "Run as administrator"
    pause
    exit /B 1
)

echo Installing required dependencies...

REM Install core dependencies and PyInstaller
echo Installing psutil, tabulate, wmi, pywin32, and pyinstaller...
pip install psutil==5.9.5 tabulate wmi==1.5.1 pywin32 pyinstaller

REM --- PYWIN32 POST-INSTALL ---
echo Running pywin32 post-install tasks...

REM The module approach is the most reliable way to run the post-install script.
python -m pywin32_postinstall -install 2>nul
if %errorLevel% equ 0 (
    echo Pywin32 post-install completed successfully via module command.
) else (
    echo Warning: pywin32 post-install failed via module command.
    echo Please ensure the pywin32 package is fully installed.
)

REM --- END PYWIN32 SECTION ---

echo.
echo Dependencies installed successfully!
echo You may need to restart your command prompt or IDE for PATH changes to take effect.
echo.
echo Press any key to exit...
pause > nul