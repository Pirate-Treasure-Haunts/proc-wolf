# Nuke Mode: Complete Threat Removal

proc-wolf's "Nuke Mode" is the ultimate response to persistent threats. This guide explains what it is, when it's used, and how it works.

## What is Nuke Mode?

Nuke Mode is proc-wolf's most aggressive response to malicious software. It's a complete removal protocol that goes beyond simply killing a process to eliminate all associated files, registry entries, and services.

Think of it as a "scorched earth" approach - it aims to remove every trace of the malicious software from your system to prevent any possibility of return.

## When is Nuke Mode Triggered?

proc-wolf uses Nuke Mode in the following scenarios:

1. **Multiple Resurrections**: When a process has been killed multiple times but keeps returning, proc-wolf escalates to Nuke Mode.
   
2. **Critical Threats**: For the most dangerous threats (threat level 4), Nuke Mode is triggered more quickly.

3. **Manual Activation**: You can manually trigger Nuke Mode for specific threats through the command-line interface.

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

## When to Use Manual Nuke Mode

Consider manual Nuke Mode when:

- You've identified malware that standard removal tools can't eliminate
- A suspicious process keeps returning after being terminated
- You need to completely remove unwanted software with no traces left

To trigger manual Nuke Mode from the command line:

```
python proc-wolf.py --nuke-process "malicious_process.exe"
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

## Conclusion

Nuke Mode is proc-wolf's ultimate defense against persistent threats. By removing all traces of malicious software, it ensures that even the most determined threats cannot return to your system.

**Note**: While Nuke Mode is designed to be thorough yet safe, it should be used with caution. Always ensure you have backups of your system before using aggressive removal techniques.