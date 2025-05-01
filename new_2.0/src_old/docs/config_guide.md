# proc-wolf Configuration Guide

This guide explains how to customize proc-wolf for your specific environment and security needs.

## Configuration Overview

While proc-wolf works out of the box with sensible defaults, you may want to customize its behavior based on your specific needs and environment. This guide explains the key configuration options.

## System Critical Process List

The `SYSTEM_CRITICAL` list in the source code contains processes that are essential for Windows to function properly. These processes are automatically trusted and will never be terminated.

### Adding Custom Applications to Safe List

If you have specific applications that you want to always trust, you can add them to the `SYSTEM_CRITICAL` list:

```python
# Add your trusted applications here
SYSTEM_CRITICAL.update([
    "myapp.exe",
    "custom-antivirus.exe",
    "company-vpn.exe"
])
```

## Trusted Publishers

The `TRUSTED_PUBLISHERS` set contains names of trusted digital signature publishers. Executables signed by these publishers are given a higher trust score.

### Adding Custom Trusted Publishers

If you use software from specific vendors that aren't in the default list, add them:

```python
# Add your trusted publishers here
TRUSTED_PUBLISHERS.update([
    "Your Company, Inc.",
    "Trusted Vendor Ltd."
])
```

## Suspicious Patterns

The `SUSPICIOUS_PATTERNS` list contains regex patterns that match common malware naming conventions. Processes matching these patterns receive a higher threat score.

### Adding Custom Suspicious Patterns

If you've encountered specific malware patterns, add them to the list:

```python
# Add suspicious patterns here
SUSPICIOUS_PATTERNS.extend([
    r'^custom_malware_pattern\.exe$',
    r'^company_specific_threat_[0-9]+\.exe$'
])
```

## Suspicious Locations

The code includes checks for processes running from unusual locations. You may want to customize the location lists based on your environment.

### Customizing Location Checks

Modify the `suspicious_locations` and `standard_locations` lists in the `is_suspicious_location` function:

```python
# Add company-specific suspicious locations
suspicious_locations.extend([
    r'D:\Unexpected',
    r'\\NetworkShare\Suspicious'
])

# Add legitimate custom locations your company uses
standard_locations.extend([
    r'C:\CustomApps',
    r'D:\CompanyTools'
])
```

## Threat Level Evaluation

The `evaluate_threat_level` function determines how suspicious a process is based on multiple factors. You can adjust the scoring weights to make certain factors more or less important.

### Adjusting Threat Scoring

For example, to make digital signature verification more important:

```python
# Digital signature check (increase weight from 1 to 2)
if not process_info['digital_signature']:
    threat_score += 2  # Increased from 1
```

## Action Levels

The `get_action_level` function determines what action to take based on the threat level and warning count. You can make this more or less aggressive.

### Making Actions More Conservative

For a more conservative approach (fewer automatic kills):

```python
def get_action_level(threat_level, warnings_count):
    if threat_level <= 1:  # TRUSTED or LOW
        return 0  # Always just MONITOR
    elif threat_level == 2:  # MEDIUM
        return min(warnings_count, 1)  # Maximum of WARN only
    elif threat_level == 3:  # HIGH
        return min(warnings_count, 2)  # Maximum of SOFT_KILL
    else:  # CRITICAL
        return min(warnings_count + 1, 3)  # Maximum of FORCE_KILL
```

## Check Interval

The `CHECK_INTERVAL` constant determines how frequently proc-wolf scans for new processes (in seconds).

### Adjusting Scanning Frequency

```python
# Scan every 10 seconds instead of 5
CHECK_INTERVAL = 10
```

## Warning Threshold

The `MAX_WARNINGS` constant determines how many warnings a process receives before stronger action is taken.

### Adjusting Warning Threshold

```python
# Give more warnings before taking action
MAX_WARNINGS = 5
```

## Database Configuration

proc-wolf uses SQLite to store process history. You can customize the database file location.

### Changing Database Location

```python
# Store database in a specific location
DB_FILE = "C:/ProcWolf/data/proc-wolf.db"
```

## Logging Configuration

You can customize how proc-wolf logs information.

### Changing Log Level

```python
# Change log level to DEBUG for more detailed logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='proc-wolf.log',
    filemode='a'
)
```

### Changing Log File Location

```python
# Store logs in a specific location
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='C:/ProcWolf/logs/proc-wolf.log',
    filemode='a'
)
```

## Advanced Configuration - Command Line Parameters

For more advanced usage, you could modify the code to accept command line parameters using Python's `argparse` module. This would allow you to specify options when launching proc-wolf:

```python
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='proc-wolf: Advanced Process Monitor')
    parser.add_argument('--check-interval', type=int, default=5, 
                        help='Interval between process checks (seconds)')
    parser.add_argument('--max-warnings', type=int, default=3,
                        help='Number of warnings before taking action')
    parser.add_argument('--db-file', type=str, default='proc-wolf.db',
                        help='Database file path')
    parser.add_argument('--log-file', type=str, default='proc-wolf.log',
                        help='Log file path')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Logging level')
    parser.add_argument('--quarantine-dir', type=str, default='./quarantine',
                        help='Directory for quarantined files')
    
    return parser.parse_args()
```

## Running proc-wolf at Startup

To ensure continuous protection, you may want to configure proc-wolf to run at system startup. Here are some methods:

### Using Task Scheduler

1. Open Task Scheduler
2. Create a new task
3. Set trigger to "At system startup"
4. Set action to run `pythonw.exe` with the path to proc-wolf.py as argument
5. Check "Run with highest privileges"

### Using Registry

You can add proc-wolf to the Windows registry to run at startup:

1. Create a .bat file that runs proc-wolf
2. Add this batch file to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`