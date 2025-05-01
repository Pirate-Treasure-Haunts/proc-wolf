# proc-wolf Executable and Background Mode Guide

This document explains how to use the various executable modes of proc-wolf for different protection scenarios.

## Available Executable Modes

proc-wolf now comes in three different executable formats:

1. **ProcWolf.exe** - System tray background monitor with GUI access
2. **ProcWolfCLI.exe** - Command-line interface with all monitoring capabilities
3. **ProcWolfService.exe** - Windows service for continuous system-level protection

Each mode serves a specific purpose in your security strategy.

## ProcWolf.exe: System Tray Monitor

The system tray version provides a user-friendly way to run proc-wolf in the background with quick access to its features.

### Key Features

- **Wolf Icon in System Tray**: Visual indicator that protection is active
- **Right-click Menu Access**:
  - Open Control Panel: Shows process list with threat assessment
  - Check Status: Displays if monitoring is active
  - Exit: Stops the background monitor
- **Low-profile Operation**: Runs silently but remains accessible
- **User-level Permissions**: Runs with the current user's permissions

### When to Use ProcWolf.exe

- For desktop users who want visible confirmation of protection
- When easy access to monitoring controls is desired
- For workstations where users need to temporarily disable protection
- When running with elevated privileges isn't an option

### Usage Instructions

1. Simply double-click `ProcWolf.exe` to start
2. The wolf icon will appear in your system tray
3. Right-click for options
4. The monitor runs until explicitly closed or until system shutdown

### Example Scenarios

- **Personal Computer**: Run with startup to maintain protection with easy access
- **Shared Workstation**: Allow users to check process status without command line
- **Temporary Monitoring**: Quick start and stop for on-demand scanning

## ProcWolfCLI.exe: Command Line Interface

The command line version provides full control over all proc-wolf features.

### Key Features

- **Complete Command Set**: Access to all proc-wolf functions
- **Scriptable Operation**: Can be used in batch files and scripts
- **Direct Control**: Immediate response to commands
- **Multiple Command Modes**: List, monitor, assess, kill, nuke, etc.

### When to Use ProcWolfCLI.exe

- When you need direct, specific control over proc-wolf functions
- For scripting automated responses to threats
- For administrative investigation of suspicious processes
- When detailed output in terminal format is needed

### Usage Instructions

```
ProcWolfCLI.exe [command] [options]
```

Common commands:
```
ProcWolfCLI.exe list --assess            # List processes with threat assessment
ProcWolfCLI.exe monitor                  # Real-time process monitoring
ProcWolfCLI.exe monitor --name chrome    # Monitor specific process
ProcWolfCLI.exe assess --pid 1234        # Assess specific process
ProcWolfCLI.exe kill --name malware.exe  # Kill a process
ProcWolfCLI.exe nuke --pid
```

### Example Scenarios

- **Security Investigation**: Directly assess suspicious processes
- **Malware Removal**: Nuke persistent threats from the command line
- **System Administration**: Monitor specific system processes
- **Automation**: Include in batch files for scheduled security checks

## ProcWolfService.exe: Windows Service

The service version runs proc-wolf as a Windows service for maximum protection and persistence.

### Key Features

- **System-level Operation**: Runs with SYSTEM privileges
- **Automatic Startup**: Starts with Windows boot
- **Persistent Protection**: Continues running regardless of user login status
- **Stealthy Operation**: No visible user interface
- **Automatic Recovery**: Restarts if terminated abnormally

### When to Use ProcWolfService.exe

- For servers that need continuous protection
- When protection must persist across user sessions
- For critical systems requiring maximum security
- When elevated privileges are needed for deep system protection

### Installation Instructions

Using the provided scripts:
1. Right-click `install.bat` and select "Run as administrator"
2. The service will be installed and started automatically

Manual installation:
```
ProcWolfService.exe --startup auto install
net start ProcWolfService
```

### Management Commands

```
net start ProcWolfService    # Start the service
net stop ProcWolfService     # Stop the service
sc query ProcWolfService     # Check service status
ProcWolfService.exe remove   # Uninstall the service
```

### Example Scenarios

- **Server Protection**: Continuous monitoring of critical servers
- **Kiosk Devices**: Protection that persists regardless of user activity
- **Corporate Workstations**: IT-managed protection that users cannot disable
- **High-Security Environments**: Maximum level of continuous protection

## Combining Multiple Modes

The different modes can work together as part of a comprehensive security strategy:

### Service + CLI Combination

- **Service Mode**: Provides continuous background protection
- **CLI Mode**: Used for on-demand investigation and control

Example workflow:
1. Install the service for persistent protection
2. Use CLI commands to investigate alerts:
   ```
   ProcWolfCLI.exe history --nuked    # Check recently nuked processes
   ProcWolfCLI.exe assess --name suspicious.exe  # Investigate a process
   ```

### Service + System Tray Combination

- **Service Mode**: Handles core protection functions with system privileges
- **System Tray Mode**: Provides user-friendly status and control

Example workflow:
1. Install the service for persistent protection
2. Run system tray version for easy access to status and controls
3. Both will monitor the same database, providing unified protection

## Choosing the Right Mode for Your Environment

| Environment | Recommended Mode | Reason |
|-------------|-----------------|--------|
| Personal Computer | System Tray | User-friendly with visual feedback |
| Corporate Workstation | Service + System Tray | Strong protection with user visibility |
| Server | Service | Maximum protection, no UI needed |
| Security Investigation | CLI | Direct control and detailed output |
| Kiosk Device | Service | Persistent protection without user interface |

## Building Custom Executables

Advanced users can customize and build their own executables using the provided build script:

1. Modify the source files as needed
2. Run the build script:
   ```
   python build_exe.py
   ```
3. Customized executables will be created in the `dist` directory

## Performance Considerations

Each mode has different performance characteristics:

- **System Tray**: Slightly higher memory usage (~50MB) due to GUI components
- **CLI**: Minimal impact when not actively running commands
- **Service**: Optimized for long-term running (~30MB constant memory usage)

For low-resource systems, the service mode provides the most efficient operation for continuous protection.

## Logging Differences

Each mode logs to different locations by default:

- **System Tray**: Logs to `%LOCALAPPDATA%\proc-wolf\proc-wolf-background.log`
- **CLI**: Logs to `proc-wolf-cli.log` in the executable directory
- **Service**: Logs to `C:\ProgramData\proc-wolf\proc-wolf-service.log`

All modes share the same process database, ensuring consistent protection and history regardless of which mode you use.