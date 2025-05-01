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

REM Install psutil
echo Installing psutil...
pip install psutil==5.9.5

REM Install tabulate
echo Installing tabulate...
pip install tabulate

REM Install WMI
echo Installing WMI...
pip install wmi==1.5.1

REM Try to install pywin32 directly from wheel
echo Attempting to install pywin32 from wheel...

REM Detect Python version
for /f "tokens=2 delims=." %%a in ('python --version 2^>^&1') do set PYVER=%%a
echo Detected Python version: 3.%PYVER%

REM Detect architecture (64-bit or 32-bit)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PROCESSOR_ARCHITECTURE | find "AMD64" > nul
if %errorLevel% equ 0 (
    set ARCH=win_amd64
    echo Detected 64-bit system
) else (
    set ARCH=win32
    echo Detected 32-bit system
)

REM Install pywin32 from wheel
echo Installing pywin32...
pip install https://github.com/mhammond/pywin32/releases/download/b306/pywin32-306-cp3%PYVER%-cp3%PYVER%-win_amd64.whl --force-reinstall

REM Run post-install script
echo Running post-install tasks...

REM First try direct module approach
python -m pywin32_postinstall -install 2>nul
if %errorLevel% neq 0 (
    echo Post-install module not found, trying alternative approach...
    
    REM Try to find the script
    for /f "tokens=*" %%a in ('dir /s /b "%PROGRAMFILES%\Python*\Lib\site-packages\pywin32_system32\scripts\pywin32_postinstall.py" 2^>nul') do (
        echo Found script: %%a
        python "%%a" -install
        if %errorLevel% equ 0 (
            echo Post-install completed successfully
        ) else (
            echo Warning: Post-install returned error code %errorLevel%
        )
    )
    
    for /f "tokens=*" %%a in ('dir /s /b "%PROGRAMFILES%\Python*\Scripts\pywin32_postinstall.py" 2^>nul') do (
        echo Found script: %%a
        python "%%a" -install
        if %errorLevel% equ 0 (
            echo Post-install completed successfully
        ) else (
            echo Warning: Post-install returned error code %errorLevel%
        )
    )
)

REM Add the pywin32 directories to PATH
echo Adding pywin32 directories to PATH...
for /f "tokens=*" %%a in ('dir /s /b "%PROGRAMFILES%\Python*\Lib\site-packages\pywin32_system32" 2^>nul') do (
    echo Adding %%a to PATH
    setx PATH "%PATH%;%%a" /M
)

for /f "tokens=*" %%a in ('dir /s /b "%PROGRAMFILES%\Python*\Lib\site-packages\win32" 2^>nul') do (
    echo Adding %%a to PATH
    setx PATH "%PATH%;%%a" /M
)

echo.
echo Dependencies installed successfully!
echo You may need to restart your system for all changes to take effect.
echo.
echo Press any key to exit...
pause > nul