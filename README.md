[README.md]

# 🐺 Proc-Wolf: Rogue Process & Service Removal Companion
**Proc-Wolf** is a lightweight background daemon that watches for suspicious or unwanted processes and takes them out. But sometimes, you might need to go full ghostbuster mode when a stubborn service or malware leftover refuses to die. This guide walks you through both.

---

### Quickstart: Using `proc_wolf.exe`
1. Double-click `proc_wolf.exe` to start watching silently in the background.
2. It will scan every few seconds and attempt to kill known bad processes listed in its internal target list.
3. Log file is written to:

`C:\Users<YourUsername>\AppData\Roaming\proc_wolf.log`

You can verify it's running via Task Manager (`proc_wolf.exe`) or by checking the log file.

---

### To Stop Proc-Wolf
- Open Task Manager → Right-click `proc_wolf.exe` → **End Task**
- Or use PowerShell:
powershell
`Stop-Process -Name proc_wolf -Force`
If scheduled via Task Scheduler, go to Task Scheduler → Task Library and disable or delete the task.

Manual Removal of Rogue Services & Processes
Sometimes, a process or service just wont go away — even after taskkill or sc delete. If that happens, follow the steps below.

## Phase 1: Identify the Threat
Open Task Manager or Process Explorer

Look for:
- Processes with missing or weird descriptions
- Names like xxxxxService_abc123
- Stuff using high CPU/RAM unexpectedly
- Suspicious command-line entries

Useful PowerShell:
powershell
`Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name, Id, CPU, Description`
`Get-CimInstance Win32_Process | Select-Object Name, CommandLine`

## Phase 2: Kill the Process
In Admin Command Prompt:

cmd
`taskkill /f /pid [PID]`
Or get the service PID first:

cmd
`sc queryex xxxxxService_name`

## Phase 3: Stop & Delete the Service
Still in Admin CMD:

cmd
`sc stop xxxxxService_name`
`sc delete xxxxxService_name`
If that doesn’t work due to permissions...

## Phase 4: Use Sysinternals Suite (Autoruns)
Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

Run Autoruns.exe as Admin
Switch to the Services tab
[Ctrl+F] the rogue service
[Right-click] → [Delete] or uncheck to disable

## Phase 5: Clean Registry (Optional)
Run regedit.exe as Admin

Navigate to:

reg
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\`
Find the exact service key (e.g., OneSyncSvc_3c981)

[Right-click] → [Delete]

### Final Cleanup
Reboot

Check:
`services.msc`
[Task Manager] → [Services]
Autoruns again
Confirm it's really gone

# Plan B: Scheduled Kill at Boot
If all else fails:

- Use Recovery Console (Shift + Restart)
- Open Command Prompt
- Delete from the offline registry or disable the task
- Bonus Tool: Process Explorer
[A superpowered Task Manager:]

Download: https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer

Run as Admin

See:
- Full process trees
- DLLs and handles
- Network activity
- Parent processes

### Tips for Detection
Look out for:
- Random suffix services (Service_9f21b)
- Services with no descriptions
- Processes that respawn after kill
- Unexpected CPU/disk/network use

🐺 Want to Customize Proc-Wolf?
Open the proc_wolf.py file and edit:

```python
TARGET_PROCESSES = {
    "badprocess.exe": {"kills": 0, "severity": 0},
    "evilscript.py": {"kills": 0, "severity": 0},
    "worm.bat": {"kills": 0, "severity": 0}
}
```

Then rebuild using:

powershell
`pyinstaller --onefile --noconsole proc_wolf.py`

Made with love for all you system defenders out there. 🐺 Stay safe.
