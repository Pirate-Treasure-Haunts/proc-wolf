#!/usr/bin/env python3
"""
Build script for creating proc-wolf executables
WITH automatic service_control.bat generation
"""

import os
import sys
import subprocess
import shutil
import time

def install_requirements():
    """Install required packages for building the exe"""
    print("Installing required packages...")
    packages = [
        "pyinstaller",
        "pywin32",
        "psutil",
        "wmi",
        "tabulate",
        "pystray",
        "pillow"
    ]
    
    # Run pip install in silent mode for cleaner output
    for package in packages:
        print(f"Installing {package}...")
        subprocess.run([sys.executable, "-m", "pip", "install", package], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("All required packages installed.")

def check_files_exist():
    """Check if all required files exist"""
    required_files = [
        "proc_wolf.py",
        "proc_wolf_full_4-0.py",
        "proc_wolf_background.py",
        "proc_wolf_service.py"
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("\nERROR: The following required files are missing:")
        for file in missing_files:
            print(f"  - {file}")
        
        print("\nPlease create these files before building the executables.")
        return False
    
    return True

def build_background_exe():
    """Build the background version of proc-wolf"""
    print("\nBuilding background executable...")
    icon_param = ["--icon=wolf.ico"] if os.path.exists("wolf.ico") else []
    
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        *icon_param,
        "--name=ProcWolf",
        "--collect-all", "pystray", 
        "--add-data=proc_wolf.py;.",
        "--add-data=proc_wolf_full_4-0.py;.",
        "proc_wolf_background.py"
    ]
    
    subprocess.run(command, check=True)
    
    if os.path.exists("./dist/ProcWolf.exe"):
        print("\nBackground executable built successfully!")
        print("Output: ./dist/ProcWolf.exe")
    else:
        print("\nERROR: Failed to build background executable")

def build_cli_exe():
    """Build the CLI version of proc-wolf"""
    print("\nBuilding CLI executable...")
    icon_param = ["--icon=wolf.ico"] if os.path.exists("wolf.ico") else []
    
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--console",
        *icon_param,
        "--name=ProcWolfCLI",
        "--add-data=proc_wolf.py;.",
        "proc_wolf_full_4-0.py"
    ]
    
    subprocess.run(command, check=True)
    
    if os.path.exists("./dist/ProcWolfCLI.exe"):
        print("\nCLI executable built successfully!")
        print("Output: ./dist/ProcWolfCLI.exe")
    else:
        print("\nERROR: Failed to build CLI executable")

def build_service_exe():
    """Build the service version of proc-wolf"""
    print("\nBuilding service executable...")
    icon_param = ["--icon=wolf.ico"] if os.path.exists("wolf.ico") else []
    
    # Include win32timezone hidden import fix
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--console",
        *icon_param,
        "--name=ProcWolfService",
        "--add-data=proc_wolf.py;.",
        "--hidden-import", "win32timezone",
        "proc_wolf_service.py"
    ]
    
    subprocess.run(command, check=True)
    
    if os.path.exists("./dist/ProcWolfService.exe"):
        print("\nService executable built successfully!")
        print("Output: ./dist/ProcWolfService.exe")
    else:
        print("\nERROR: Failed to build service executable")

def create_installer_script():
    """Create a batch script to install the service"""
    os.makedirs("./dist", exist_ok=True)
    
    install_script = """@echo off
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

:: Stop the service if it's already running
echo Checking if service already exists...
sc query "ProcWolfService" >nul 2>&1
if %errorLevel% equ 0 (
    echo Found existing service, stopping it first...
    net stop "ProcWolfService" >nul 2>&1
    timeout /t 2 /nobreak >nul
)

:: Remove existing service if it exists
sc query "ProcWolfService" >nul 2>&1
if %errorLevel% equ 0 (
    echo Removing existing service...
    "%~dp0ProcWolfService.exe" remove
    timeout /t 2 /nobreak >nul
)

:: Install the service
echo Installing service...
"%~dp0ProcWolfService.exe" --startup auto install

:: Start the service
echo Starting Proc-Wolf Service...
net start "ProcWolfService"

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
    echo Installation had issues
    echo ===================================
    echo.
    echo The service might not have started correctly.
    echo Check the logs for more information.
    echo.
)

pause
"""
    
    uninstall_script = """@echo off
echo ===================================
echo Proc-Wolf Uninstallation
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

echo Stopping Proc-Wolf Service...
net stop "ProcWolfService" 2>nul
echo.
echo Removing Proc-Wolf Service...
"%~dp0ProcWolfService.exe" remove
echo.
echo Uninstallation complete!
echo.
pause
"""
    
    # Create install script
    with open("./dist/install.bat", "w") as file:
        file.write(install_script)
    
    # Create uninstall script
    with open("./dist/uninstall.bat", "w") as file:
        file.write(uninstall_script)
    
    print("\nInstallation scripts created:")
    print("- ./dist/install.bat")
    print("- ./dist/uninstall.bat")

def create_service_control_script():
    """Create a service control script for easy management"""
    os.makedirs("./dist", exist_ok=True)
    
    control_script = """@echo off
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
"""
    
    with open("./dist/service_control.bat", "w") as file:
        file.write(control_script)
    
    print("\nService control script created:")
    print("- ./dist/service_control.bat")

def create_readme():
    """Create a readme file"""
    readme = """# Proc-Wolf Process Monitor v4.1.1

## Files Included
- ProcWolf.exe - Background monitor with system tray icon
- ProcWolfCLI.exe - Command line interface for direct control
- ProcWolfService.exe - Windows service for continuous monitoring
- install.bat - Script to install the Windows service
- uninstall.bat - Script to uninstall the Windows service
- service_control.bat - Service management utility

## Installation
1. Right-click on install.bat and select "Run as administrator"
2. The service will be installed and started automatically

## Service Management
Use service_control.bat for easy service management:
- 1. STATUS - Check if service is running
- 2. START - Start the service
- 3. STOP - Stop gracefully
- 4. RESTART - Full restart
- 5. KILL - Force kill all instances
- 6. CLEAN - Complete removal
- 7. DEBUG - Run in debug mode

## Usage
- **Background Monitor**: Run ProcWolf.exe to start the system tray monitor
- **Command Line Interface**: Run ProcWolfCLI.exe with the following commands:
  - `ProcWolfCLI.exe list` - List all processes
  - `ProcWolfCLI.exe list --assess` - List all processes with threat assessment
  - `ProcWolfCLI.exe assess --name chrome.exe` - Assess a specific process
  - `ProcWolfCLI.exe kill --name badprocess.exe` - Kill a process
  - `ProcWolfCLI.exe nuke --name malware.exe` - Completely remove a process
  - `ProcWolfCLI.exe monitor` - Monitor processes in real-time
  - `ProcWolfCLI.exe history` - View process history

## Uninstallation
1. Right-click on uninstall.bat and select "Run as administrator"
2. The service will be stopped and removed

## Log Files
- Service logs: C:\\ProgramData\\proc-wolf\\proc-wolf-service.log
- Background logs: %LOCALAPPDATA%\\proc-wolf\\proc-wolf-background.log
- CLI logs: proc-wolf-cli.log (in the same directory as the executable)

## Troubleshooting
- If service won't stop: Use service_control.bat option 5 (KILL)
- If service won't start: Check C:\\ProgramData\\proc-wolf\\proc-wolf-service.log
- For debugging: Use service_control.bat option 7 (DEBUG)

## Version History
- v4.1.1: Fixed service startup/shutdown, added comprehensive Windows process recognition
- v4.0.0: Initial release with multi-layered threat detection
"""
    
    # Create readme
    with open("./dist/README.txt", "w") as file:
        file.write(readme)
    
    print("\nReadme file created:")
    print("- ./dist/README.txt")

def main():
    """Main function"""
    print("===================================")
    print("Proc-Wolf EXE Builder v4.1.1")
    print("===================================")
    
    # Kill any running instances before building
    print("\nChecking for running instances...")
    try:
        # Try to stop service gracefully first
        subprocess.run(["net", "stop", "ProcWolfService"], capture_output=True, timeout=5)
        time.sleep(1)
    except:
        pass
    
    # Force kill any remaining instances
    processes_to_kill = ["ProcWolfService.exe", "ProcWolf.exe", "ProcWolfCLI.exe"]
    for proc in processes_to_kill:
        try:
            result = subprocess.run(["taskkill", "/F", "/IM", proc], capture_output=True, text=True)
            if "SUCCESS" in result.stdout:
                print(f"  Killed running {proc}")
        except:
            pass
    
    # Install requirements
    install_requirements()
    
    # Check if all required files exist
    if not check_files_exist():
        return
    
    # Build executables
    try:
        # Clean up previous builds before starting
        if os.path.exists("./build"):
            shutil.rmtree("./build")
        if os.path.exists("./ProcWolfService.spec"):
             os.remove("./ProcWolfService.spec")
        
        build_background_exe()
        build_cli_exe()
        build_service_exe()
        
        # Create installation scripts
        create_installer_script()
        
        # Create service control script
        create_service_control_script()
        
        # Create readme
        create_readme()
        
        print("\n===================================")
        print("All executables built successfully!")
        print("===================================")
        print("\nGenerated files in ./dist:")
        print("  - ProcWolf.exe (System tray monitor)")
        print("  - ProcWolfCLI.exe (Command line interface)")
        print("  - ProcWolfService.exe (Windows service)")
        print("  - install.bat (Service installer)")
        print("  - uninstall.bat (Service uninstaller)")
        print("  - service_control.bat (Service manager)")
        print("  - README.txt (Documentation)")
        print("\nReady for deployment!")
        print("===================================")
        
    except Exception as e:
        print(f"\nERROR: Failed to build executables: {e}")

if __name__ == "__main__":
    main()
