#!/usr/bin/env python3
"""
Build script for creating proc-wolf executables
"""

import os
import sys
import subprocess
import shutil

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
        # Use --collect-all for libraries that often need hidden imports (like pystray/PIL)
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
    
    # *** KEY FIX: Add --hidden-import win32timezone ***
    # In build_service_exe() function
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--console",
        *icon_param,
        "--name=ProcWolfService",
        "--add-data=proc_wolf.py;.",
        "--hidden-import", "win32timezone",  # ← THIS IS CRITICAL
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
    # Ensure dist directory exists
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

def create_readme():
    """Create a readme file"""
    readme = """# Proc-Wolf Process Monitor

## Files Included
- ProcWolf.exe - Background monitor with system tray icon
- ProcWolfCLI.exe - Command line interface for direct control
- ProcWolfService.exe - Windows service for continuous monitoring
- install.bat - Script to install the Windows service
- uninstall.bat - Script to uninstall the Windows service

## Installation
1. Right-click on install.bat and select "Run as administrator"
2. The service will be installed and started automatically

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
"""
    
    # Create readme
    with open("./dist/README.txt", "w") as file:
        file.write(readme)
    
    print("\nReadme file created:")
    print("- ./dist/README.txt")

def main():
    """Main function"""
    print("===================================")
    print("Proc-Wolf EXE Builder")
    print("===================================")
    
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
        
        # Create readme
        create_readme()
        
        print("\nAll executables built successfully!")
        print("Files are available in the ./dist directory")
        print("===================================")
    except Exception as e:
        print(f"\nERROR: Failed to build executables: {e}")

if __name__ == "__main__":
    main()