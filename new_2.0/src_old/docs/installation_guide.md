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
   - `requirements.txt`

## Step 3: Install Dependencies

Open Command Prompt as Administrator, navigate to the proc-wolf directory, and run:

```
pip install -r requirements.txt
```

This will install all the required Python packages:
- psutil
- pywin32
- wmi

## Step 4: Run proc-wolf

### Basic Run

To run proc-wolf with default settings, open Command Prompt as Administrator, navigate to the proc-wolf directory, and run:

```
python proc-wolf.py
```

The program will start monitoring processes and log activities to `proc-wolf.log` in the same directory.

### First-Run Checks

When you first run proc-wolf, it will:

1. Create a SQLite database file (`proc-wolf.db`) to store process information
2. Begin monitoring all running processes
3. Log its activities to `proc-wolf.log`

## Step 5: Set Up Automatic Startup (Optional)

### Method A: Using Task Scheduler

To have proc-wolf start automatically when your computer boots:

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

### Method B: Using a Windows Service

For more advanced users, you can set up proc-wolf as a Windows service using NSSM (Non-Sucking Service Manager):

1. Download NSSM from [nssm.cc](https://nssm.cc/download)
2. Extract the appropriate executable (nssm.exe) based on your system architecture
3. Open Command Prompt as Administrator and navigate to where you extracted nssm.exe
4. Run:
   ```
   nssm install proc-wolf
   ```
5. In the dialog that appears:
   - Set "Path" to your Python executable
   - Set "Arguments" to the full path to proc-wolf.py
   - Set "Startup directory" to the directory containing proc-wolf.py
6. Switch to the "Details" tab:
   - Set "Display name" to "proc-wolf Process Monitor"
   - Set "Description" to "Monitors and manages suspicious processes"
7. Click "Install service"

The service will now start automatically when Windows boots.

## Step 6: Verify Installation

To verify proc-wolf is running correctly:

1. Check the log file (`proc-wolf.log`) for entries
2. Look for processes in Task Manager or Process Explorer with "python" or "pythonw" running

## Troubleshooting

### Missing Dependencies

If you see errors about missing modules, ensure you ran the `pip install -r requirements.txt` command correctly. You can install individual packages if needed:

```
pip install psutil
pip install pywin32
pip install wmi
```

### Permission Issues

Many process operations require administrator privileges. If you see "Access Denied" errors:

1. Make sure you ran Command Prompt as Administrator
2. Try launching Python with elevated privileges

### Database Errors

If you encounter database errors:

1. Make sure the directory containing proc-wolf has write permissions
2. If the database becomes corrupted, stop proc-wolf, delete `proc-wolf.db`, and restart

### Python Path Issues

If Windows cannot find Python:

1. Ensure Python is in your PATH environment variable
2. Try using the full path to the Python executable: