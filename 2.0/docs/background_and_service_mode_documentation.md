# Running proc-wolf in Background and Service Modes

This guide explains how to use the new background and service modes of proc-wolf for continuous protection without visible windows.

## Overview of Background Running Modes

proc-wolf now supports three different ways to run in the background:

1. **System Tray Mode** (ProcWolf.exe)
   - Runs in the background with a wolf icon in your system tray
   - Provides quick access through right-click menu
   - Perfect for desktop users who want easy access to controls

2. **Windows Service Mode** (ProcWolfService.exe)
   - Runs as a system service that starts with Windows
   - Continues monitoring even when no user is logged in
   - Ideal for servers and systems requiring consistent protection

3. **Command Line Mode** (ProcWolfCLI.exe)
   - The original proc-wolf interface with all commands
   - Can be used alongside the other modes for direct control

## System Tray Mode (ProcWolf.exe)

The system tray version provides a user-friendly way to run proc-wolf in the background.

### Features

- **Wolf Icon** in the system tray indicates proc-wolf is running
- **Right-click Menu** provides quick access to common functions:
  - Open Control Panel: Shows process list with threat assessment
  - Check Status: Displays if monitoring is active
  - Exit: Stops the background monitor

### Installation

No special installation is required. Simply run `ProcWolf.exe` to start the background monitor.

### Auto-start with Windows

To have proc-wolf start automatically when you log in:

1. Create a shortcut to ProcWolf.exe
2. Press Win+R, type `shell:startup` and press Enter
3. Move the shortcut to the Startup folder that opens

### Usage Tips

- The system tray icon changes color based on threat level:
  - Gray: Normal operation
  - Yellow: Low-level threats detected
  - Red: Critical threats requiring attention
- Hover over the icon to see a summary of current status

## Windows Service Mode (ProcWolfService.exe)

The service mode runs proc-wolf as a Windows service for maximum protection and persistence.

### Features

- **Automatic Startup**: Starts automatically with Windows
- **System-level Access**: Runs with elevated privileges
- **Persistent Protection**: Works even when no user is logged in
- **Crash Recovery**: Service restarts automatically if it fails

### Installation

1. Right-click `install.bat` and select "Run as administrator"
2. The script will:
   - Stop any existing proc-wolf service
   - Install the new service
   - Start the service

### Manual Installation Commands

If you prefer to install manually, use these commands in an Administrator command prompt:

```cmd
# Install the service
ProcWolfService.exe --startup auto install

# Start the service
net start ProcWolfService

# Check service status
sc query ProcWolfService

# Stop the service
net stop ProcWolfService

# Remove the service
ProcWolfService.exe remove
```

### Uninstallation

1. Right-click `uninstall.bat` and select "Run as administrator"
2. The script will stop and remove the service

### Log File Locations

The service logs all activity to:
```
C:\ProgramData\proc-wolf\proc-wolf-service.log
```

## Command Line Mode (ProcWolfCLI.exe)

The command line version provides direct control and can be used alongside the background modes.

### Usage with Background Modes

You can use ProcWolfCLI.exe to check or modify settings while ProcWolf.exe or ProcWolfService.exe is running:

```cmd
# List all processes with threat assessment
ProcWolfCLI.exe list --assess

# Kill a suspicious process
ProcWolfCLI.exe kill --name suspicious.exe --force

# Completely remove a malicious process
ProcWolfCLI.exe nuke --name malware.exe
```

## Combining Multiple Modes

The different modes can work together for comprehensive protection:

- **Service Mode** (ProcWolfService.exe) for continuous background protection
- **System Tray Mode** (ProcWolf.exe) for easy user access
- **Command Line Mode** (ProcWolfCLI.exe) for direct control when needed

## Troubleshooting Background Modes

### Service Won't Start

If the service fails to start:

1. Check the service log: `C:\ProgramData\proc-wolf\proc-wolf-service.log`
2. Verify you have administrator privileges
3. Make sure no other instance of proc-wolf is running with conflicting settings
4. Check Windows Event Viewer for service-related errors

### System Tray Icon Not Appearing

If the system tray icon doesn't appear:

1. Check Task Manager to verify ProcWolf.exe is running
2. Look in the "hidden icons" section of your taskbar
3. Restart the process
4. Check the log file for errors

### Conflicts Between Modes

If you experience conflicts when running multiple modes:

1. Each mode uses the same database, so they will share process history
2. The service mode has priority for active protection
3. Only run one active monitoring instance (either service or system tray)
4. Use ProcWolfCLI.exe for commands regardless of which background mode is running

## Resource Considerations

Running proc-wolf in background mode is designed to be resource-efficient:

- **Service Mode**: Uses minimal resources with efficient scanning intervals
- **System Tray Mode**: Slightly higher resource usage to maintain UI elements
- **Memory Usage**: Typically under 50MB for monitoring functions
- **CPU Impact**: Less than 1% during idle monitoring, may increase briefly during scans

For constrained systems, use Service Mode for the smallest footprint.

## Security Considerations

- **Service Mode** runs with SYSTEM privileges, providing the highest level of access
- **System Tray Mode** runs with the privileges of the logged-in user
- For maximum security, use Service Mode with Command Line as needed
- Always run installation scripts as Administrator