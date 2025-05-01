# Nuke Mode: Complete Threat Removal

proc-wolf's "Nuke Mode" is the ultimate response to persistent threats. This guide explains what it is, when it's used, and how it works with the new executable versions.

## What is Nuke Mode?

Nuke Mode is proc-wolf's most aggressive response to malicious software. It's a complete removal protocol that goes beyond simply killing a process to eliminate all associated files, registry entries, and services.

Think of it as a "scorched earth" approach - it aims to remove every trace of the malicious software from your system to prevent any possibility of return.

## When is Nuke Mode Triggered?

proc-wolf uses Nuke Mode in the following scenarios:

1. **Multiple Resurrections**: When a process has been killed multiple times but keeps returning, proc-wolf escalates to Nuke Mode.
   
2. **Critical Threats**: For the most dangerous threats (threat level 4), Nuke Mode is triggered more quickly.

3. **Manual Activation**: You can manually trigger Nuke Mode for specific threats through any of the interfaces.

## How Nuke Mode Works

When Nuke Mode is triggered, proc-wolf performs a comprehensive removal process:

### 1. Process Termination
- Forces immediate termination of the malicious process

### 2. Service Removal
- Identifies any associated Windows services
- Stops and disables these services
- Deletes service entries from the system

### 3. File System Cleanup
- Searches for related files across critical system locations:
  - User profile directories
  - Program Files
  - Temporary folders
  - AppData directories
  - Browser extension folders
- Removes all identified files and directories

### 4. Registry Cleanup
- Scans multiple registry locations:
  - HKEY_CURRENT_USER
  - HKEY_LOCAL_MACHINE
  - Run and RunOnce keys
  - Service entries
  - Application paths
- Deletes all registry entries associated with the threat

### 5. Quarantine
- If removal fails, moves critical files to a quarantine folder
- Preserves evidence for later analysis

### 6. Persistence Prevention
- Adds rules to prevent the threat from restarting
- Monitors for resurrection attempts

## Nuke Mode Safety Features

To prevent damage to legitimate system files:

1. **Safe List Protection**: System-critical processes are protected from Nuke Mode
2. **Confirmation Checks**: Multiple verification steps before deletion
3. **Quarantine Instead of Delete**: When in doubt, files are quarantined rather than deleted
4. **Detailed Logging**: All actions are extensively logged

## Using Nuke Mode with Different Executable Versions

### From the Command Line Interface (ProcWolfCLI.exe)

The CLI provides the most control over Nuke Mode operations:

```
# Nuke a process by PID with confirmation prompt
ProcWolfCLI.exe nuke --pid 1234

# Nuke a process by name with confirmation prompt
ProcWolfCLI.exe nuke --name malware.exe

# Force nuke without confirmation (use with caution)
ProcWolfCLI.exe nuke --name malware.exe --force
```

### From the System Tray Interface (ProcWolf.exe)

The system tray version can trigger Nuke Mode through its control panel:

1. Right-click the wolf icon in the system tray
2. Select "Open Control Panel"
3. Find the suspicious process in the list
4. Right-click and select "Nuke Process"
5. Confirm when prompted

### From the Service Mode (ProcWolfService.exe)

The service can automatically trigger Nuke Mode for critical threats based on threat assessment:

1. The service continuously monitors all processes
2. When it detects a critical threat, it can automatically escalate to Nuke Mode
3. All actions are logged to `C:\ProgramData\proc-wolf\proc-wolf-service.log`

## Viewing Nuke Mode History

To see a history of Nuke Mode operations:

```
ProcWolfCLI.exe history --nuked
```

This shows all processes that have been nuked, when they were removed, and what artifacts were cleaned up.

## Recovering from Nuke Mode (Quarantine Management)

If a legitimate file was incorrectly nuked, you can recover it from quarantine:

```
# List quarantined files
ProcWolfCLI.exe quarantine --list

# Restore a file by ID
ProcWolfCLI.exe quarantine --restore 3
```

## Example Nuke Mode Scenario

### Before Nuke Mode:
1. proc-wolf detects suspicious process "cryptominer.exe"
2. Standard termination is attempted twice
3. Process reappears each time
4. Resurrection count reaches threshold

### During Nuke Mode:
1. Force kills "cryptominer.exe"
2. Identifies and removes associated service "cryptoservice"
3. Deletes files from:
   - C:\Users\[username]\AppData\Roaming\Cryptominer\
   - C:\ProgramData\Cryptominer\
   - Other locations
4. Removes registry entries:
   - HKCU\Software\Cryptominer
   - HKLM\SYSTEM\CurrentControlSet\Services\cryptoservice
5. Quarantines executable file

### After Nuke Mode:
1. The threat is completely removed
2. System is monitored for resurrection attempts
3. Entry added to database of nuked processes
4. Detailed logs in the appropriate log file based on which mode triggered it

## Service-Based vs. User-Initiated Nuke Mode

### Service-Based (Automatic)
- **Trigger**: Based on threat level and resurrection count
- **Permissions**: Runs with SYSTEM privileges for maximum access
- **Confirmation**: No user confirmation (pre-authorized)
- **Speed**: Immediate response without waiting for user
- **Logging**: Detailed logs in service log file

### User-Initiated (CLI or System Tray)
- **Trigger**: Manual command from user
- **Permissions**: Runs with user's privileges (may need elevation)
- **Confirmation**: Requires explicit confirmation unless --force is used
- **Speed**: Depends on user response to prompts
- **Logging**: Detailed logs in respective log files

## Best Practices for Nuke Mode

1. **Always backup important data** before using Nuke Mode on critical systems
2. **Start with less aggressive options** before escalating to Nuke Mode
3. **Check the quarantine** after nuking to verify what was removed
4. **Review logs** to understand what actions were taken
5. **Consider using the --force option only** in extreme cases
6. **Run as administrator** for maximum effectiveness

## Conclusion

Nuke Mode is proc-wolf's ultimate defense against persistent threats. By removing all traces of malicious software, it ensures that even the most determined threats cannot return to your system.

The addition of multiple executable modes makes Nuke Mode more accessible and powerful, allowing both automated protection through the service and direct control through the CLI and system tray interfaces.

**Note**: While Nuke Mode is designed to be thorough yet safe, it should be used with caution. Always ensure you have backups of your system before using aggressive removal techniques.