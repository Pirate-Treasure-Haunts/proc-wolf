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

## New: Configuring Background and Service Modes

The new background and service modes provide additional configuration options.

### System Tray Mode Configuration

You can customize the system tray behavior by modifying the `proc_wolf_background.py` file:

```python
# Change the icon refresh rate (seconds)
ICON_REFRESH_INTERVAL = 10

# Enable/disable tooltip notifications
ENABLE_NOTIFICATIONS = True

# Customize the system tray menu items
def create_menu(self):
    return pystray.Menu(
        pystray.MenuItem("My Custom Control Panel", self.open_control_panel),
        pystray.MenuItem("Check Status", self.check_status),
        pystray.MenuItem("Custom Command", self.custom_function),
        pystray.MenuItem("Exit", self.exit)
    )

# Add a custom function
def custom_function(self, icon, item):
    # Your custom code here
    subprocess.Popen([sys.executable, 'proc_wolf_full_3-0.py', 'custom', '--option'])
```

### Windows Service Configuration

You can customize the Windows service behavior by modifying the `proc_wolf_service.py` file:

```python
# Change service name and display name
class ProcWolfService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'CustomProcWolfService'
    _svc_display_name_ = 'Custom Proc-Wolf Process Monitor'
    _svc_description_ = 'Your custom description here'
    
# Modify checking interval in the monitoring loop
def monitor_with_stop_check(self, db):
    # ...
    time.sleep(10)  # Check every 10 seconds instead of default
    
# Change log file location
log_file = os.path.join('C:/CustomLogs', 'proc-wolf-service.log')
```

### Executable Build Configuration

You can customize the built executables by modifying the `build_exe.py` file:

```python
# Change executable names
"--name=MyCustomProcWolf",  # Instead of ProcWolf

# Add custom icon
"--icon=my-custom-icon.ico",  # Instead of wolf.ico

# Include additional files
"--add-data=my-config.json;.",

# Add hidden imports
"--hidden-import=my_custom_module",
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
    
    # New args for background mode
    parser.add_argument('--background', action='store_true',
                        help='Run in background mode with system tray icon')
    parser.add_argument('--no-notifications', action='store_true',
                        help='Disable system tray notifications')
    
    return parser.parse_args()
```

## Configuring Multiple Running Modes

When running proc-wolf in multiple modes (service, system tray, and CLI), you might want to ensure they work together harmoniously:

### Shared Database Configuration

Ensure all modes use the same database file for consistent history and threat tracking:

```python
# In proc_wolf.py
DB_FILE = os.path.join(os.environ.get('PROGRAMDATA', ''), 'proc-wolf', 'proc-wolf.db')

# In proc_wolf_service.py
DB_FILE = os.path.join(os.environ.get('PROGRAMDATA', ''), 'proc-wolf', 'proc-wolf.db')

# In proc_wolf_background.py
DB_FILE = os.path.join(os.environ.get('PROGRAMDATA', ''), 'proc-wolf', 'proc-wolf.db')
```

### Different Log Files for Different Modes

Use distinct log files for each mode to make troubleshooting easier:

```python
# CLI mode
logging.basicConfig(filename='proc-wolf-cli.log')

# Service mode
logging.basicConfig(filename=os.path.join(os.environ.get('PROGRAMDATA', ''), 'proc-wolf', 'proc-wolf-service.log'))

# System tray mode
logging.basicConfig(filename=os.path.join(os.environ.get('LOCALAPPDATA', ''), 'proc-wolf', 'proc-wolf-tray.log'))
```

## Running proc-wolf at Startup

To ensure continuous protection, you may want to configure proc-wolf to run at system startup. Here are some methods:

### Method A: Using Task Scheduler (Original Python Version)

1. Open Task Scheduler
2. Create a new task
3. Set trigger to "At system startup"
4. Set action to run `pythonw.exe` with the path to proc-wolf.py as argument
5. Check "Run with highest privileges"

### Method B: Using Startup Folder (System Tray Version)

1. Create a shortcut to ProcWolf.exe
2. Press Win+R, type `shell:startup` and press Enter
3. Move the shortcut to the Startup folder that opens

### Method C: Using Windows Service (Service Version)

1. Install the service with auto-start:
   ```
   ProcWolfService.exe --startup auto install
   ```
2. Start the service:
   ```
   net start ProcWolfService
   ```

## Configuration for Enterprise Deployment

For large-scale deployment in an enterprise environment, you might want to:

1. Create a standard configuration file that can be distributed
2. Use Group Policy to deploy the service version
3. Configure centralized logging
4. Implement centralized quarantine management

Example Group Policy script for service installation:

```batch
@echo off
REM Deploy proc-wolf service
cd "%~dp0"
ProcWolfService.exe --startup auto install
net start ProcWolfService
```

## Conclusion

proc-wolf's flexibility allows it to be customized for various environments and security needs. By adjusting configuration options in the source code or using command line parameters, you can fine-tune its behavior to match your specific requirements.

With the new background and service modes, proc-wolf provides even more customization options for how it runs and interacts with the system, allowing for a seamless security solution that works the way you need it to.