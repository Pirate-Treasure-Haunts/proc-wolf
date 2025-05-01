# proc-wolf Advanced Usage Guide

This guide covers advanced techniques and use cases for proc-wolf beyond the basic functionality.

## Command Line Interface

proc-wolf includes a powerful CLI for advanced control:

### Listing Processes with Advanced Filtering

```bash
# List all processes with threat assessment, sorted by threat level
python proc_wolf_cli.py list --assess --sort threat

# Filter processes by name pattern
python proc_wolf_cli.py list --filter chrome --assess

# Limit output to top 5 CPU-consuming processes
python proc_wolf_cli.py list --sort cpu --limit 5
```

### Real-time Process Monitoring

```bash
# Monitor a specific process by PID
python proc_wolf_cli.py monitor --pid 1234

# Monitor all processes matching a name pattern
python proc_wolf_cli.py monitor --name chrome
```

### Detailed Threat Assessment

```bash
# Get comprehensive threat assessment for a specific process
python proc_wolf_cli.py assess --pid 1234

# Assess all processes matching a name
python proc_wolf_cli.py assess --name svchost
```

### Advanced Process Termination

```bash
# Force kill a process
python proc_wolf_cli.py kill --pid 1234 --force

# Kill all instances of a process
python proc_wolf_cli.py kill --name malware.exe --force
```

### Nuke Mode Operation

```bash
# Completely remove a process and all its artifacts
python proc_wolf_cli.py nuke --pid 1234

# Nuke all instances of a process without confirmation (use with caution)
python proc_wolf_cli.py nuke --name malware.exe --force
```

### Quarantine Management

```bash
# List all quarantined files
python proc_wolf_cli.py quarantine --list

# Restore a quarantined file (by ID from list)
python proc_wolf_cli.py quarantine --restore 3

# Permanently delete a quarantined file
python proc_wolf_cli.py quarantine --delete 2
```

### Process History Analysis

```bash
# View history of recently detected processes
python proc_wolf_cli.py history

# Check history for a specific process
python proc_wolf_cli.py history --name svchost.exe

# View history of all nuked processes
python proc_wolf_cli.py history --nuked
```

## Integration with System Tools

### Setting Up Scheduled Monitoring

Use Windows Task Scheduler to run proc-wolf regularly:

1. Open Task Scheduler
2. Create a Basic Task
3. Set trigger to "Daily" or "At startup"
4. Set action to "Start a program"
5. Program/script: `pythonw.exe`
6. Add arguments: `C:\path\to\proc_wolf.py --quiet`

### Creating Custom Response Scripts

You can create custom scripts that respond to proc-wolf's warnings:

```python
# Example: Custom handler for CRITICAL threats
import sqlite3
import subprocess
import time

DB_FILE = "proc-wolf.db"

def check_critical_threats():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Find CRITICAL threat processes from the last hour
    cursor.execute("""
        SELECT id, name, path FROM process_history 
        WHERE threat_level = 4 
        AND last_seen > datetime('now', '-1 hour')
    """)
    
    critical_threats = cursor.fetchall()
    conn.close()
    
    for threat_id, name, path in critical_threats:
        # Custom response - e.g., email admin, create incident ticket
        print(f"CRITICAL THREAT: {name}")
        
        # Example: Run emergency backup
        subprocess.run(["backup_critical_data.bat"])
        
        # Example: Isolate from network
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])

if __name__ == "__main__":
    while True:
        check_critical_threats()
        time.sleep(300)  # Check every 5 minutes
```

## Customizing Threat Detection

### Creating Custom Threat Patterns

You can extend proc-wolf's suspicious patterns by modifying the code:

```python
# Add custom threat patterns
SUSPICIOUS_PATTERNS.extend([
    # Company-specific patterns
    r'^company_[a-z0-9]{8}\.exe$',
    
    # Industry-specific threats
    r'^pos_[a-z]+\.exe$',  # Point-of-sale malware pattern
    
    # Recently observed threat patterns
    r'^[a-z]{3}loader[0-9]{2}\.exe$'
])
```

### Adding Custom Location Checks

Customize suspicious location checks for your environment:

```python
# Add company-specific trusted locations
standard_locations.extend([
    r'C:\Company\ApprovedTools',
    r'D:\EnterpriseApps'
])

# Add company-specific suspicious locations
suspicious_locations.extend([
    r'\\FileServer\Public',
    r'C:\Builds\Temp'
])
```

## Advanced Nuke Mode Techniques

### Creating Targeted Nuke Scripts

You can create targeted nuke scripts for specific malware families:

```python
# Example: Targeted cleaner for a specific malware family
def nuke_cryptominer_family(process_name):
    """Special nuke procedure for cryptominer family"""
    # Find and kill all related processes
    related_processes = ["xmrig", "minerd", "cpuminer", process_name]
    for proc in related_processes:
        subprocess.run(["taskkill", "/F", "/IM", proc])
    
    # Remove specific registry keys
    registry_locations = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        # Add specific known locations for this malware
    ]
    
    for location in registry_locations:
        subprocess.run(["reg", "delete", location, "/v", "Miner", "/f"])
    
    # Clean specific file locations
    locations_to_clean = [
        os.path.join(os.environ.get('APPDATA', ''), "Roaming", "Miner"),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), "Temp", "xmr"),
        # Add other known locations
    ]
    
    for location in locations_to_clean:
        if os.path.exists(location):
            shutil.rmtree(location)
```

### Creating Persistent Protection Rules

After nuking a threat, you can add persistent protection rules:

```python
def add_persistent_protection(threat_name, file_hash=None):
    """Add persistent protection against a specific threat"""
    # Add to blocked processes list (requires custom implementation)
    with open("blocked_processes.txt", "a") as f:
        f.write(f"{threat_name}\n")
    
    # Add hash to blocklist if available
    if file_hash:
        with open("blocked_hashes.txt", "a") as f:
            f.write(f"{file_hash}\n")
    
    # Create file system protection (example using Windows FSR)
    subprocess.run([
        "fltmc.exe", "loads"  # Check if filter driver is loaded
    ])
    
    # Add network blocking rule
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=BlockMalware", "dir=out