# proc-wolf Installation Guide

This guide walks you through installing and setting up proc-wolf on your Windows system.

## Prerequisites

Before installing proc-wolf, ensure your system meets the following requirements:

- Windows 7/8/10/11
- Python 3.6 or higher
- Administrator privileges (recommended)

## Step 1: Install Python

If you don't already have Python installed:

1. Download the latest Python 3 installer from [python.org](https://www.python.org/downloads/)
2. Run the installer
3. Check "Add Python to PATH" during installation
4. Complete the installation

To verify Python is installed correctly, open Command Prompt and type:
```
python --version
```

You should see the Python version number.

## Step 2: Download proc-wolf

### Option A: Clone from GitHub (if using Git)

```
git clone https://github.com/your-username/proc-wolf.git
cd proc-wolf
```

### Option B: Download Files Directly

1. Create a folder for proc-wolf (e.g., `C:\proc-wolf`)
2. Download the following files to this folder:
   - `proc-wolf.py`
   - `proc_wolf_full_3-0.py`
   - `proc_wolf_background.py` (for system tray mode)
   - `proc_wolf_service.py` (for Windows service)
   - `requirements.txt`
   - Build scripts and installation files

## Step 3: Install Dependencies

Open Command Prompt as Administrator, navigate to the proc-wolf directory, and run:

```
pip install -r requirements.txt
```

This will install all the required Python packages:
- psutil
- pywin32
- wmi
- tabulate
- pystray (for system tray mode)
- pillow (for icon creation)

## Step 4: Build Executables (NEW)

proc-wolf now supports building executable files for easier distribution and background running. To create these executables:

1. Run the icon creation script first:
   ```
   python create_icon.py
   ```

2. Then run the build script:
   ```
   python build_exe.py
   ```

This will create three executable files in the `dist` directory:
- `ProcWolf.exe` - System tray version
- `ProcWolfCLI.exe` - Command line interface
- `ProcWolfService.exe` - Windows service

## Step 5: Running proc-wolf

### Option A: Direct Python Execution

To run the original script with default settings, open Command Prompt as Administrator, navigate to the proc-wolf directory, and run:

```
python proc_wolf_full_3-0.py
```

### Option B: Using Built Executables (NEW)

#### System Tray Mode
For a background process with system tray icon:
```
ProcWolf.exe
```

#### Command Line Interface
For direct command-line control:
```
ProcWolfCLI.exe [command] [options]
```
Examples:
```
ProcWolfCLI.exe list --assess
ProcWolfCLI.exe monitor
```

#### Windows Service Mode
For running as a service (requires Administrator rights):
```
ProcWolfService.exe --startup auto install
net start ProcWolfService
```

Alternatively, right-click on `install.bat` and select "Run as administrator"

## Step 6: Set Up Automatic Startup

### Method A: Using Task Scheduler (Original Version)

For the Python script version:

1. Open Task Scheduler from Start menu
2. Click "Create Basic Task"
3. Enter a name (e.g., "proc-wolf") and description
4. Select "When the computer starts" as trigger
5. Select "Start a program" as action
6. Browse to your Python executable (usually `C:\Python39\python.exe`)
7. In "Add arguments", add the full path to proc-wolf.py (e.g., `C:\proc-wolf\proc-wolf.py`)
8. In "Start in", add the directory containing proc-wolf.py (e.g., `C:\proc-wolf`)
9. Check "Open the Properties dialog for this task when I click Finish"
10. Click Finish
11. In the Properties dialog, check "Run with highest privileges"
12. Click OK

### Method B: Using Startup Folder (NEW - For System Tray Version)

For the system tray executable:

1. Create a shortcut to ProcWolf.exe
2. Press Win+R, type `shell:startup` and press Enter
3. Move the shortcut to the Startup folder that opens

### Method C: Using Windows Service (NEW)

For the most comprehensive protection:

1. Right-click on install.bat and select "Run as administrator"
2. The service will be installed and set to start automatically with Windows

## Step 7: Verify Installation

To verify proc-wolf is running correctly:

### For Python Script or CLI Version
- Check the log file (`proc-wolf.log`) for entries
- Look for processes in Task Manager with "python" running

### For System Tray Version
- Look for the wolf icon in your system tray (bottom right of taskbar)
- Right-click the icon and select "Check Status"

### For Service Version
- Open Services (Win+R, type `services.msc`)
- Look for "Proc-Wolf Process Monitor" in the list
- Status should be "Running"
- Check the service log at `C:\ProgramData\proc-wolf\proc-wolf-service.log`

## Troubleshooting

### Missing Dependencies

If you see errors about missing modules, ensure you ran the `pip install -r requirements.txt` command correctly. You can install individual packages if needed:

```
pip install psutil pywin32 wmi tabulate pystray pillow
```

### Permission Issues

Many process operations require administrator privileges. If you see "Access Denied" errors:

1. Make sure you ran Command Prompt as Administrator
2. Try launching Python with elevated privileges

### Service Won't Start

If the Windows service fails to start:

1. Check the service log at `C:\ProgramData\proc-wolf\proc-wolf-service.log`
2. Make sure no other instance of proc-wolf is running with conflicting settings
3. Verify you have administrator privileges
4. Try reinstalling the service:
   ```
   ProcWolfService.exe remove
   ProcWolfService.exe --startup auto install
   ```

### System Tray Icon Not Appearing

If the system tray icon doesn't appear:

1. Check Task Manager to verify ProcWolf.exe is running
2. Look in the "hidden icons" section of your taskbar
3. Restart the process

## Uninstalling proc-wolf

### Uninstalling the Python Version
- Delete the proc-wolf directory
- Remove any startup tasks you created

### Uninstalling the Service Version
- Right-click on uninstall.bat and select "Run as administrator"
- Or run these commands:
  ```
  net stop ProcWolfService
  ProcWolfService.exe remove
  ```

### Uninstalling the System Tray Version
- Exit the program from the system tray icon
- Remove any shortcuts from the Startup folder