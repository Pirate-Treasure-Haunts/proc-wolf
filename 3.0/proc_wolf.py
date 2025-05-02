#!/usr/bin/env python3
"""
proc-wolf: Advanced Process Monitor and Security Tool
----------------------------------------------------
Monitors, detects, and handles suspicious processes using a multi-layered
verification approach and escalating response system.
"""

import os
import sys
import time
import logging
import platform
import subprocess
import psutil
import ctypes
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
import hashlib
import sqlite3
import re

# Try to import winreg
try:
    import winreg
except ImportError:
    # For compatibility with older Python versions
    import _winreg as winreg

# Conditionally import win32 modules with proper error handling
win32_available = False
wmi_available = False

try:
    # First try the standard import
    import win32api
    import win32process
    import win32security
    import win32gui
    win32_available = True
except ImportError:
    # Then try the import with the new structure that might be used in newer versions
    try:
        from win32 import api as win32api
        from win32 import process as win32process
        from win32 import security as win32security
        from win32 import gui as win32gui
        win32_available = True
    except ImportError:
        logging.warning("win32api modules not available. Some functions will be limited.")

try:
    import wmi
    wmi_available = True
except ImportError:
    logging.warning("wmi module not available. Some functions will be limited.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='proc-wolf.log',
    filemode='a'
)

# Console handler for immediate feedback
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Global Constants
VERSION = "1.0.0"
CONFIG_FILE = "proc-wolf.config"
DB_FILE = "proc-wolf.db"
MAX_WARNINGS = 5  # Increased from 3 to be more conservative
CHECK_INTERVAL = 5  # seconds

# Threat Levels
THREAT_LEVEL = {
    0: "TRUSTED",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL"
}

# Action Levels
ACTION_LEVEL = {
    0: "MONITOR",
    1: "WARN",
    2: "SOFT_KILL",
    3: "FORCE_KILL",
    4: "PREVENT_RESURRECTION"
}

# System-critical process list (base level hardcoded protection)
SYSTEM_CRITICAL = {
    # Windows core processes
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "explorer.exe", "svchost.exe",
    "taskmgr.exe", "dwm.exe", "conhost.exe", "sihost.exe", "fontdrvhost.exe",
    "ctfmon.exe", "ShellExperienceHost.exe", "SearchUI.exe", "RuntimeBroker.exe",
    "SecurityHealthService.exe", "SgrmBroker.exe", "spoolsv.exe", "lsm.exe",
    "ntoskrnl.exe", "Registry", "Idle", "Memory Compression",

    # System utilities
    "regedit.exe", "notepad.exe", "cmd.exe", "powershell.exe", "mmc.exe",
    "control.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
    "taskhost.exe", "taskhostw.exe", "dllhost.exe",

    # Windows Defender
    "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe", "SecurityHealthSystray.exe",

    # System updates
    "wuauclt.exe", "UsoClient.exe", "MusNotification.exe", "WaaSMedicSvc.exe",

    # Basic user apps
    "calc.exe", "SystemSettings.exe", "SearchApp.exe",

    # Our own process - Explicitly added here for absolute certainty
    "ProcWolf.exe", "procwolf.exe", "PROCWOLF.EXE",
    "ProcWolfCLI.exe", "procwolfcli.exe", "PROCWOLFCLI.EXE",
    "ProcWolfService.exe", "procwolfservice.exe", "PROCWOLFSERVICE.EXE",
    "python.exe", "Python.exe", "PYTHON.EXE",
    os.path.basename(sys.executable).lower(), # Add the actual executable name running the script

    # Browsers (common and generally trusted)
    "chrome.exe", "msedge.exe", "firefox.exe", "vivaldi.exe", "brave.exe", "opera.exe",

    # Developer tools (common and generally trusted)
    "code.exe", "idea64.exe", "pycharm64.exe", "eclipse.exe", "atom.exe", "sublime_text.exe",
    "devenv.exe", "rider64.exe", "webstorm64.exe", "phpstorm64.exe", "clion64.exe",
    "androidstudio64.exe", "powershell.exe", "powershell_ise.exe",

    # Terminal/console apps (common and generally trusted)
    "WindowsTerminal.exe", "cmd.exe", "wt.exe", "alacritty.exe", "cmder.exe", "hyper.exe",
    "gitbash.exe", "ConEmu64.exe", "FluentTerminal.App.exe",

    # System tools (common and generally trusted)
    "SnippingTool.exe", "ScreenClippingHost.exe", "snippingtool.exe", "mspaint.exe",
    "PhotosApp.exe", "calculator.exe", "notepad.exe", "wordpad.exe",
    "explorer.exe", "controlpanel.exe", "taskmgr.exe", "perfmon.exe",
}

# Known trusted publishers (for digital signature verification)
TRUSTED_PUBLISHERS = {
    "Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher",
    "Google Inc", "Google LLC", "Mozilla Corporation", "Apple Inc.", "Adobe Inc.",
    "Adobe Systems", "Dropbox, Inc", "Valve", "Valve Corporation",
    "Steam", "NVIDIA Corporation", "Advanced Micro Devices, Inc.",
    "Intel Corporation", "Dell Inc.", "Hewlett-Packard", "Lenovo", "Logitech",
    "Realtek Semiconductor", "Oracle Corporation", "VMware, Inc.",
}

# Suspicious patterns in process names (regex)
SUSPICIOUS_PATTERNS = [
    r'^[a-zA-Z0-9]{16,}\.exe$',  # Long random name
    r'^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}\.exe$',  # GUID-like
    r'^[a-zA-Z0-9]{8,}\.(exe|dll|scr)$',  # Random name with executable extension
    r'^(svc|service|agent|host|system|windows|microsoft)[0-9]{2,}\.exe$',  # System-looking with numbers
    r'^[a-zA-Z0-9]{1,3}\.exe$',  # Extremely short executable name
    r'(backdoor|trojan|keylog|hack|crack|steal|spy)',  # Suspicious words
]

# Process repository for tracking state between checks
process_repository = {}

# Process warning counts
warnings = {}

# Secure whitelist implementation
import hmac
import hashlib
import base64

class SecureWhitelist:
    def __init__(self, whitelist_file, hmac_key=None):
        self.whitelist_file = whitelist_file

        # If no key provided, generate one based on machine-specific identifiers
        # This makes the key unique to this machine and harder to predict
        if hmac_key is None:
            self.hmac_key = self._generate_machine_key()
        else:
            self.hmac_key = hmac_key

        self.whitelist = self._load_whitelist()
        
        # Make sure critical system processes are ALWAYS in the whitelist
        self._ensure_critical_processes()

    def _generate_machine_key(self):
        """Generate a machine-specific key that's hard to predict"""
        try:
            # Gather machine-specific information
            import uuid
            machine_id = str(uuid.getnode())  # MAC address as integer

            # Add Windows-specific identifiers if available
            try:
                machine_guid = None
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                    machine_guid = winreg.QueryValueEx(key, "MachineGuid")[0]
                if machine_guid:
                    machine_id += machine_guid
            except:
                pass

            # Add disk volume serial if available
            if win32_available:
                try:
                    drive = os.path.splitdrive(os.environ.get('SystemRoot', 'C:'))[0] + '\\'
                    volume_info = win32api.GetVolumeInformation(drive)
                    volume_serial = str(volume_info[1])
                    machine_id += volume_serial
                except:
                    pass

            # Create a strong key from machine-specific information
            key = hashlib.pbkdf2_hmac(
                'sha256',
                machine_id.encode(),
                b'proc-wolf-salt',
                100000
            )
            return key
        except Exception as e:
            # Fallback if there's an error
            logging.warning(f"Error generating machine key: {e}. Using default key.")
            return b'proc-wolf-secure-whitelist-default-key'

    def _load_whitelist(self):
        """Load whitelist from file with signature verification"""
        whitelist = set()

        if not os.path.exists(self.whitelist_file):
            # Create default whitelist if it doesn't exist
            self._create_default_whitelist()
            return self.whitelist

        try:
            with open(self.whitelist_file, 'r') as f:
                content = f.read()

            # Split signature and data
            parts = content.strip().split('---SIGNATURE---')
            if len(parts) != 2:
                logging.warning("Whitelist file appears to be tampered with (no valid signature). Using empty whitelist.")
                return set()

            data, signature_b64 = parts

            # Verify signature
            signature = base64.b64decode(signature_b64)
            computed_signature = hmac.new(
                self.hmac_key,
                data.encode(),
                hashlib.sha256
            ).digest()

            if not hmac.compare_digest(signature, computed_signature):
                logging.warning("Whitelist file signature verification failed! Possible tampering detected.")
                return set()

            # Parse entries
            for line in data.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.add(line.lower())

            return whitelist

        except Exception as e:
            logging.error(f"Error loading whitelist: {e}")
            return set()

    def _save_whitelist(self):
        """Save whitelist to file with signature"""
        try:
            # Convert set to sorted list for consistent signatures
            entries = sorted(self.whitelist)

            # Create content with comments
            content = "# proc-wolf secure whitelist\n"
            content += "# DO NOT MODIFY THIS FILE MANUALLY - USE THE MANAGEMENT INTERFACE\n"
            content += "# Any manual changes will invalidate the security signature\n\n"

            # Add entries
            for entry in entries:
                content += f"{entry}\n"

            # Generate signature
            signature = hmac.new(
                self.hmac_key,
                content.encode(),
                hashlib.sha256
            ).digest()
            signature_b64 = base64.b64encode(signature).decode()

            # Write to file
            with open(self.whitelist_file, 'w') as f:
                f.write(content)
                f.write("---SIGNATURE---")
                f.write(signature_b64)

            return True
        except Exception as e:
            logging.error(f"Error saving whitelist: {e}")
            return False

    def _ensure_critical_processes(self):
        """Ensure critical system processes are always whitelisted"""
        critical_processes = [
            "explorer.exe",  # Windows Explorer
            "taskmgr.exe",   # Task Manager
            "procwolf.exe",  # Our own executables
            "procwolfcli.exe",
            "procwolfservice.exe",
            "proc_wolf_background.py",
            "python.exe",    # Python interpreter (if running as script)
            os.path.basename(sys.executable).lower()  # Current executable
        ]
        
        # Add system paths
        critical_paths = [
            "C:\\Windows\\System32/",
            "C:\\Windows\\explorer.exe"
        ]
        
        # Add all critical processes to whitelist
        modified = False
        for proc in critical_processes:
            if proc.lower() not in self.whitelist:
                self.whitelist.add(proc.lower())
                modified = True
                logging.info(f"Added critical process to whitelist: {proc}")
                
        # Add all critical paths to whitelist
        for path in critical_paths:
            if path.lower() not in self.whitelist:
                self.whitelist.add(path.lower())
                modified = True
                logging.info(f"Added critical path to whitelist: {path}")
                
        # Save if modified
        if modified:
            self._save_whitelist()

    def _create_default_whitelist(self):
        """Create default whitelist with common trusted applications"""
        self.whitelist = {
            # Browsers
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "vivaldi.exe",
            "brave.exe",
            "opera.exe",

            # Development tools
            "code.exe",
            "idea64.exe",
            "pycharm64.exe",
            "eclipse.exe",
            "visual studio.exe",

            # System utilities
            "windowsterminal.exe",
            "cmd.exe",
            "powershell.exe",
            "snippingtool.exe",
            "explorer.exe",    # CRITICAL - Windows Explorer

            # Our own tools - ESSENTIAL TO PREVENT SELF-NUKING!
            "ProcWolf.exe", "procwolf.exe", "PROCWOLF.EXE",
            "ProcWolfCLI.exe", "procwolfcli.exe", "PROCWOLFCLI.EXE",
            "ProcWolfService.exe", "procwolfservice.exe", "PROCWOLFSERVICE.EXE",
            "python.exe", "Python.exe", "PYTHON.EXE",
            "proc_wolf_background.py",  # Add background script explicitly

            # Standard paths (special format with trailing slash to indicate directories)
            "C:\\Program Files\\Microsoft VS Code/",
            "C:\\Program Files\\Vivaldi/",
            "C:\\Program Files\\Google\\Chrome/",
            "C:\\Windows\\System32/"
        }
        self._save_whitelist()

    def is_whitelisted(self, process_name, process_path=None):
        """Check if a process is whitelisted"""
        # Check direct executable name match
        if process_name.lower() in self.whitelist:
            return True

        # Check path against directory whitelist
        if process_path:
            # Directory entries have a trailing slash in our format
            for entry in self.whitelist:
                if entry.endswith('/'):
                    dir_path = entry[:-1]  # Remove the trailing slash
                    if process_path.lower().startswith(dir_path.lower()):
                        return True
                    
            # Special check for critical system binaries
            if process_path.lower().startswith("c:\\windows\\") and process_name.lower() in SYSTEM_CRITICAL:
                return True

        return False

    def fixed_add_entry(self, entry):
        """Add an entry to the whitelist"""
        entry = entry.lower()
        # FIX: Check if already in whitelist before adding (no already_in_whitelist reference)
        if entry not in self.whitelist:
            self.whitelist.add(entry)
            return self._save_whitelist()
        return True

    def remove_entry(self, entry):
        """Remove an entry from the whitelist"""
        entry = entry.lower()
        # FIX: Check if entry is in whitelist before removing 
        if entry in self.whitelist:
            # Don't allow removing critical processes
            if entry in ["explorer.exe", "taskmgr.exe", "procwolf.exe", "procwolfcli.exe", "procwolfservice.exe", "python.exe"]:
                logging.warning(f"Attempt to remove critical process from whitelist: {entry}")
                return False
            self.whitelist.remove(entry)
            return self._save_whitelist()
        return True

    def get_entries(self):
        """Get all whitelist entries"""
        return sorted(self.whitelist)

# Initialize the secure whitelist
WHITELIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proc-wolf-whitelist.dat")
secure_whitelist = SecureWhitelist(WHITELIST_FILE)

# Whitelist functions
def is_whitelisted(process_name, process_path=None):
    """Check if a process is whitelisted using the secure system"""
    return secure_whitelist.is_whitelisted(process_name, process_path)

def add_to_whitelist(process_name, process_path=None):
    """Add an application to the whitelist"""
    # Add the executable name
    secure_whitelist.add_entry(process_name)

    # If it's a directory path, add with trailing slash
    if process_path and os.path.isdir(process_path):
        secure_whitelist.add_entry(process_path + "/")
    # If it's a file path, add the directory containing it
    elif process_path and os.path.isfile(process_path):
        dir_path = os.path.dirname(process_path) + "/"
        secure_whitelist.add_entry(dir_path)

def remove_from_whitelist(entry):
    """Remove an entry from the whitelist"""
    secure_whitelist.remove_entry(entry)

def get_whitelist_entries():
    """Get all whitelist entries for display"""
    return secure_whitelist.get_entries()

class Database:
    """SQLite database for persistent storage of process information"""

    def __init__(self, db_file):
        self.db_file = db_file
        self._init_db()

    def _init_db(self):
        """Initialize the database schema if it doesn't exist"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS process_history (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            path TEXT,
            cmd_line TEXT,
            hash TEXT,
            digital_signature TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            threat_level INTEGER,
            times_killed INTEGER DEFAULT 0,
            trusted BOOLEAN
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS resurrections (
            id INTEGER PRIMARY KEY,
            process_id INTEGER,
            timestamp TIMESTAMP,
            kill_method TEXT,
            FOREIGN KEY (process_id) REFERENCES process_history(id)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS nuked_processes (
            id INTEGER PRIMARY KEY,
            process_id INTEGER,
            name TEXT,
            path TEXT,
            timestamp TIMESTAMP,
            artifacts_removed INTEGER,
            registry_keys_removed INTEGER,
            service_removed BOOLEAN,
            success BOOLEAN,
            FOREIGN KEY (process_id) REFERENCES process_history(id)
        )
        ''')

        conn.commit()
        conn.close()

    def add_or_update_process(self, process_info):
        """Add new process or update existing one"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Check if process exists
        cursor.execute(
            "SELECT id, times_killed FROM process_history WHERE hash = ? OR (name = ? AND path = ?)",
            (process_info['hash'], process_info['name'], process_info['path'])
        )

        result = cursor.fetchone()

        if result:
            # Update existing process
            process_id, times_killed = result
            cursor.execute(
                """
                UPDATE process_history SET
                last_seen = ?, times_killed = ?, threat_level = ?
                WHERE id = ?
                """,
                (
                    datetime.now().isoformat(),
                    times_killed,
                    process_info['threat_level'],
                    process_id
                )
            )
            conn.commit()
            conn.close()
            return process_id
        else:
            # Insert new process
            cursor.execute(
                """
                INSERT INTO process_history
                (name, path, cmd_line, hash, digital_signature, first_seen, last_seen, threat_level, trusted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    process_info['name'],
                    process_info['path'],
                    process_info['cmd_line'],
                    process_info['hash'],
                    process_info['digital_signature'],
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    process_info['threat_level'],
                    process_info['trusted']
                )
            )
            process_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return process_id

    def record_resurrection(self, process_id, kill_method):
        """Record when a process resurrects after being killed"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO resurrections (process_id, timestamp, kill_method) VALUES (?, ?, ?)",
            (process_id, datetime.now().isoformat(), kill_method)
        )

        # Increment times_killed counter
        cursor.execute(
            "UPDATE process_history SET times_killed = times_killed + 1 WHERE id = ?",
            (process_id,)
        )

        conn.commit()
        conn.close()

    def get_process_history(self, process_name=None, process_path=None, process_hash=None):
        """Get process history by name, path or hash"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        query = "SELECT * FROM process_history WHERE 1=1"
        params = []

        if process_name:
            query += " AND name = ?"
            params.append(process_name)

        if process_path:
            query += " AND path = ?"
            params.append(process_path)

        if process_hash:
            query += " AND hash = ?"
            params.append(process_hash)

        cursor.execute(query, params)
        result = cursor.fetchone()
        conn.close()

        return result

    def record_nuke_operation(self, process_id, name, path, artifacts_removed, registry_keys_removed, service_removed, success):
        """Record a nuke operation in the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO nuked_processes
            (process_id, name, path, timestamp, artifacts_removed, registry_keys_removed, service_removed, success)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                process_id,
                name,
                path,
                datetime.now().isoformat(),
                artifacts_removed,
                registry_keys_removed,
                service_removed,
                success
            )
        )

        conn.commit()
        conn.close()

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_process_hash(process_path):
    """Get SHA-256 hash of the process executable"""
    try:
        if not os.path.exists(process_path):
            return None

        with open(process_path, "rb") as f:
            file_hash = hashlib.sha256()
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                file_hash.update(chunk)

        return file_hash.hexdigest()
    except:
        return None

def check_digital_signature(process_path):
    """Check if the process is digitally signed by a trusted publisher"""
    try:
        if not process_path or not os.path.exists(process_path):
            return None

        # Try multiple methods to get signature information

        # Method 1: Try win32api if available
        if win32_available:
            try:
                # Use GetFileVersionInfo instead of the non-existent GetSignatureName
                info = win32api.GetFileVersionInfo(process_path, "\\")

                # Look for company name in version info
                try:
                    lang, codepage = win32api.GetFileVersionInfo(process_path, '\\VarFileInfo\\Translation')[0]
                    string_file_info = f'\\StringFileInfo\\{lang:04x}{codepage:04x}\\CompanyName'
                    company_name = win32api.GetFileVersionInfo(process_path, string_file_info)

                    if company_name:
                        for trusted in TRUSTED_PUBLISHERS:
                            if trusted.lower() in company_name.lower():
                                return company_name

                        return company_name  # Return the company name even if not trusted
                except:
                    pass
            except:
                # Failed to get info using win32api, continue to other methods
                pass

        # Method 2: Use PowerShell to check signature
        try:
            ps_cmd = f'Get-AuthenticodeSignature -FilePath "{process_path}" | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject'
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=3
            )

            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass

        # Method 3: Use WMI if available
        if wmi_available:
            try:
                c = wmi.WMI()
                for s in c.Win32_Service():
                    if s.PathName and process_path.lower() in s.PathName.lower():
                        return s.Description or "Service: " + s.DisplayName
            except:
                pass

        # None of the methods worked
        return None
    except:
        return None

def is_suspicious_name(process_name):
    """Check if the process name matches suspicious patterns"""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, process_name, re.IGNORECASE):
            return True
    return False

def is_suspicious_location(process_path):
    """Check if process is running from a suspicious location"""
    if not process_path:
        return True

    suspicious_locations = [
        os.environ.get('TEMP', ''),
        os.environ.get('TMP', ''),
        r'C:\Users\Public',
        r'C:\ProgramData\Temp',
    ]

    # Check standard locations - processes outside these might be suspicious
    standard_locations = [
        r'C:\Program Files',
        r'C:\Program Files (x86)',
        r'C:\Windows',
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
    ]

    # Directly in suspicious location
    for loc in suspicious_locations:
        if loc and process_path.startswith(loc):
            return True

    # Not in any standard location
    in_standard = False
    for loc in standard_locations:
        if process_path.startswith(loc):
            in_standard = True
            break

    # Additional checks for processes outside standard locations
    if not in_standard:
        # Check if it's in a user profile but not in a standard subfolder
        if r'C:\Users' in process_path:
            standard_user_folders = ['Desktop', 'Documents', 'Downloads', 'AppData']
            is_in_standard_user_folder = False

            for folder in standard_user_folders:
                if fr'\{folder}\\' in process_path:
                    is_in_standard_user_folder = True
                    break

            if not is_in_standard_user_folder:
                return True

    # Check if file is hidden - using os.stat instead of win32api
    try:
        if win32_available:
            attrs = win32api.GetFileAttributes(process_path)
            return bool(attrs & 2)  # 2 is the hidden attribute
        else:
            # Alternative check without win32api
            # Check if the file or parent directory starts with a dot
            path_obj = Path(process_path)
            return path_obj.name.startswith('.') or any(p.name.startswith('.') for p in path_obj.parents)
    except:
        pass

    return False

def has_suspicious_behavior(pid, proc_info=None):
    """Check for suspicious process behavior"""
    try:
        if not proc_info:
            proc_info = psutil.Process(pid)

        # Check for suspicious traits
        suspicious_traits = []

        # High CPU or memory usage
        try:
            if proc_info.cpu_percent(interval=0.1) > 80:
                suspicious_traits.append("High CPU usage")
        except:
            pass

        try:
            if proc_info.memory_percent() > 25:
                suspicious_traits.append("High memory usage")
        except:
            pass

        # Check open files - hidden/temp locations
        try:
            for file in proc_info.open_files():
                if 'temp' in file.path.lower() or '$recycle.bin' in file.path.lower():
                    suspicious_traits.append(f"Accessing suspicious file: {file.path}")
        except:
            pass

        # Check network connections - suspicious ports or connections
        try:
            for conn in proc_info.connections():
                # Check for commonly abused ports
                suspicious_ports = [4444, 31337, 1337, 666, 6666, 1234, 12345, 54321]
                if conn.laddr.port in suspicious_ports or conn.raddr and conn.raddr.port in suspicious_ports:
                    suspicious_traits.append(f"Suspicious network port: {conn.laddr.port}")
        except:
            pass

        return suspicious_traits if suspicious_traits else None
    except:
        return None

def is_interactive_process(pid):
    """Check if a process has visible windows (likely user interactive)"""
    try:
        if not win32_available:
            return False

        def callback(hwnd, hwnds):
            if win32gui.IsWindowVisible(hwnd) and win32gui.IsWindowEnabled(hwnd):
                _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                if found_pid == pid:
                    hwnds.append(hwnd)
            return True

        hwnds = []
        win32gui.EnumWindows(callback, hwnds)
        return len(hwnds) > 0
    except:
        # If we can't check, default to False
        return False

def is_active_application(pid):
    """Check if this is an application the user is actively using"""
    try:
        if not win32_available:
            return False

        # Get foreground window
        foreground_hwnd = win32gui.GetForegroundWindow()
        if foreground_hwnd:
            _, foreground_pid = win32process.GetWindowThreadProcessId(foreground_hwnd)

            # Check if this is the foreground process
            if foreground_pid == pid:
                return True

            # Also check parent process - might be a child of active app
            try:
                process = psutil.Process(pid)
                parent = process.parent()
                if parent and parent.pid == foreground_pid:
                    return True
            except:
                pass

        return False
    except:
        # If we can't check, default to False
        return False

def confirm_nuke(process_name, pid):
    """Show a confirmation dialog before nuking a process"""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()  # Hide the main window

        # Make sure the dialog appears on top
        root.attributes('-topmost', True)

        result = messagebox.askyesno(
            "CRITICAL WARNING - Nuke Confirmation",
            f"proc-wolf wants to COMPLETELY REMOVE '{process_name}' (PID: {pid}).\n\n"
            f"This will delete all related files and registry entries.\n\n"
            f"Are you ABSOLUTELY SURE this is malware and not a legitimate application?",
            icon=messagebox.WARNING
        )

        root.destroy()
        return result
    except:
        # If GUI isn't available, fall back to console
        print("\n" + "!" * 80)
        print("WARNING: NUKE MODE WILL COMPLETELY REMOVE ALL TRACES OF THIS PROCESS")
        print("This includes files, registry entries, and services associated with it.")
        print("!" * 80)
        print(f"\nTarget: {process_name} (PID: {pid})")

        confirmation = input("\nAre you ABSOLUTELY SURE you want to proceed? (type 'NUKE' to confirm): ")
        return confirmation == "NUKE"

def evaluate_threat_level(process_info):
    """
    Evaluate the threat level of a process based on multiple factors
    Returns: threat_level (0-4)
    """
    process_name_lower = process_info['name'].lower()
    process_path_lower = process_info['path'].lower() if process_info['path'] else None
    cmd_line_lower = process_info['cmd_line'].lower() if process_info['cmd_line'] else None

    # **CRITICAL FIRST-PASS TRUST CHECKS**
    
    # Critical system process immediate trust - no further checks needed
    critical_system_processes = [
        'explorer.exe', 'taskmgr.exe', 'winlogon.exe', 'services.exe', 
        'lsass.exe', 'svchost.exe', 'csrss.exe', 'smss.exe', 'wininit.exe'
    ]
    
    if process_name_lower in critical_system_processes:
        return 0  # TRUSTED - No further checks

    # Our program and control panel immediate trust
    our_executables = [
        'procwolf.exe', 'procwolfcli.exe', 'procwolfservice.exe',
        'proc_wolf.py', 'proc_wolf_background.py', 'proc_wolf_service.py', 
        'proc_wolf_full_3-0.py'
    ]
    
    # Special check for our own processes
    if any(exe in process_name_lower for exe in our_executables):
        return 0  # TRUSTED
        
    # If it's the current Python process running our code, trust it immediately
    if process_name_lower == 'python.exe':
        # Check for our scripts in command line
        if cmd_line_lower and any(script in cmd_line_lower for script in our_executables):
            return 0  # TRUSTED
            
        # Also trust if it's the currently running process
        try:
            if os.getpid() == process_info['pid']:
                return 0  # TRUSTED
        except:
            pass

    # Check against the main SYSTEM_CRITICAL list
    if process_name_lower in [x.lower() for x in SYSTEM_CRITICAL]:
        return 0  # TRUSTED

    # Check against the secure whitelist
    if is_whitelisted(process_info['name'], process_info['path']):
        return 0  # Always trust whitelisted processes

    # **THREAT SCORING (Only if not already deemed trusted)**
    threat_score = 0

    # Digital signature check - REDUCED WEIGHT
    if not process_info['digital_signature']:
        threat_score += 0.5  # Reduced from 1
    elif not any(trusted.lower() in process_info['digital_signature'].lower() for trusted in TRUSTED_PUBLISHERS):
        threat_score += 0.25  # Reduced from 0.5

    # Suspicious name patterns
    if is_suspicious_name(process_info['name']):
        threat_score += 1.0  # Reduced from 1.5

    # Suspicious location - REDUCED WEIGHT
    if is_suspicious_location(process_info['path']):
        threat_score += 0.5  # Reduced from 1

    # Suspicious behavior - REDUCED WEIGHT
    if process_info['suspicious_behavior']:
        threat_score += len(process_info['suspicious_behavior']) * 0.25  # Reduced from 0.5

    # Add immunity for interactive applications (less strict check here)
    # If a process has a visible window, it's likely a legitimate user application
    try:
        has_window = is_interactive_process(process_info['pid'])
        if has_window:
            threat_score -= 0.75  # Slightly less reduction than before but still significant
            # Ensure score doesn't go below zero
            if threat_score < 0:
                 threat_score = 0
    except:
        pass

    # Map score to threat level with HIGHER THRESHOLDS
    if threat_score <= 0.75:  # Increased from 0.5
        return 0  # TRUSTED
    elif threat_score <= 2.0:  # Increased from 1.5
        return 1  # LOW
    elif threat_score <= 3.0:  # Increased from 2.5
        return 2  # MEDIUM
    elif threat_score <= 4.0:  # Increased from 3.5
        return 3  # HIGH
    else:
        return 4  # CRITICAL

def get_action_level(threat_level, warnings_count):
    """Determine what action to take based on threat level and warnings"""
    if threat_level == 0:  # TRUSTED
        return 0  # MONITOR
    elif threat_level == 1:  # LOW
        return 0  # Always just MONITOR, never escalate
    elif threat_level == 2:  # MEDIUM
        # More conservative escalation - need 5+ warnings for WARN
        return min(max(0, warnings_count - 5), 1)
    elif threat_level == 3:  # HIGH
        # More conservative escalation - need 8+ warnings for SOFT_KILL
        return min(max(0, warnings_count - 8), 2)
    else:  # CRITICAL
        # More conservative escalation - need 4+ warnings for FORCE_KILL
        return min(max(0, warnings_count - 4), 3)

def kill_process(pid, force=False):
    """Kill a process by PID"""
    try:
        process = psutil.Process(pid)
        if force:
            process.kill()  # SIGKILL equivalent
        else:
            process.terminate()  # SIGTERM equivalent

        # Allow some time for process to terminate
        gone, still_alive = psutil.wait_procs([process], timeout=3)
        return len(gone) > 0
    except:
        return False

def prevent_resurrection(pid, process_name, process_path):
    """Prevent a process from starting again"""
    try:
        # First, force kill the process
        kill_process(pid, force=True)

        # If it was a service, try to disable it
        if wmi_available:
            try:
                # Try to get the service name from the process
                wmi_obj = wmi.WMI()
                services = wmi_obj.Win32_Service(ProcessId=pid)

                if services:
                    service = services[0]
                    service_name = service.Name

                    # Stop the service
                    logging.info(f"{log_prefix} - Stopping service: {service_name}")
                    service.StopService()

                    # Disable the service
                    logging.info(f"{log_prefix} - Disabling service: {service_name}")
                    service.ChangeStartMode("Disabled")

                    # Try to delete the service using sc delete
                    logging.info(f"{log_prefix} - Removing service: {service_name}")
                    subprocess.run(["sc", "delete", service_name], check=False)

                    service_removed = True
            except Exception as e:
                logging.error(f"{log_prefix} - Error handling service: {e}")

        # Move the executable to quarantine if possible
        if process_path and os.path.exists(process_path):
            try:
                quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
                if not os.path.exists(quarantine_dir):
                    os.makedirs(quarantine_dir)

                # Move to quarantine with timestamped name to avoid conflicts
                quarantine_path = os.path.join(
                    quarantine_dir,
                    f"{os.path.basename(process_path)}.{int(time.time())}.quarantine"
                )

                os.rename(process_path, quarantine_path)
                logging.info(f"Moved {process_path} to quarantine: {quarantine_path}")
            except Exception as e:
                logging.error(f"Failed to quarantine {process_path}: {e}")

        return True
    except Exception as e:
        logging.error(f"Failed to prevent resurrection of {process_name} (PID: {pid}): {e}")
        return False

def get_process_info(proc):
    """Get detailed process information for evaluation"""
    try:
        pid = proc.pid
        name = proc.name()

        try:
            path = proc.exe()
        except (psutil.AccessDenied, FileNotFoundError):
            path = None

        try:
            cmd_line = " ".join(proc.cmdline())
        except (psutil.AccessDenied, FileNotFoundError):
            cmd_line = None

        # Get process hash if path is available
        if path and os.path.exists(path):
            file_hash = get_process_hash(path)
        else:
            file_hash = None

        # Check digital signature
        digital_signature = check_digital_signature(path) if path else None

        # Check if process is elevated (simplified for non-win32 environment)
        try:
            elevated = bool(proc.username() and 'admin' in proc.username().lower()) or proc.nice() < 0
        except:
            elevated = False

        # Check for suspicious behavior
        suspicious_behavior = has_suspicious_behavior(pid, proc)

        # Create process info dictionary
        process_info = {
            "pid": pid,
            "name": name,
            "path": path,
            "cmd_line": cmd_line,
            "hash": file_hash,
            "digital_signature": digital_signature,
            "elevated": elevated,
            "suspicious_behavior": suspicious_behavior,
            "threat_level": 0,  # Will be evaluated later
            "trusted": False    # Will be evaluated later
        }

        # Evaluate threat level
        process_info["threat_level"] = evaluate_threat_level(process_info)

        # Mark as trusted if threat level is 0
        process_info["trusted"] = (process_info["threat_level"] == 0)

        return process_info
    except Exception as e:
        logging.error(f"Error getting process info: {e}")
        return None

def init_database():
    """Initialize the application database"""
    try:
        return Database(DB_FILE)
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}")
        sys.exit(1)

def monitor_processes(db):
    """Main monitoring function"""
    logging.info(f"proc-wolf v{VERSION} started. Watching processes...")

    # Dictionary to track previous state
    previous_pids = set()

    while True:
        try:
            # Get all current processes
            current_processes = {}
            current_pids = set()

            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pid = proc.pid
                    current_pids.add(pid)

                    # Skip if we already know this process is trusted (check before getting full info)
                    if pid in process_repository and process_repository[pid]["trusted"]:
                         current_processes[pid] = process_repository[pid] # Keep in current processes
                         continue

                    # Get detailed information about the process
                    process_info = get_process_info(proc)
                    if not process_info:
                        continue

                    # Store in our current process dictionary
                    current_processes[pid] = process_info

                    # Add or update in database
                    db_id = db.add_or_update_process(process_info)
                    process_info["db_id"] = db_id

                    # Update our repository
                    process_repository[pid] = process_info


                    # Check if process requires action (only if not trusted)
                    if not process_info["trusted"]:
                        process_name = process_info["name"]

                        # Check if this is an active application (user is using it)
                        if is_active_application(pid):
                            logging.info(f"Process {process_name} (PID: {pid}) appears suspicious but is currently active - monitoring only")
                            continue  # Skip to next process


                        # Initialize or increment warning count
                        if process_name not in warnings:
                            warnings[process_name] = 0
                        else:
                            warnings[process_name] += 1

                        # Determine action based on threat level and warnings
                        action_level = get_action_level(process_info["threat_level"], warnings[process_name])

                        # Log the detection
                        logging.warning(
                            f"Suspicious process: {process_name} (PID: {pid}), "
                            f"Threat: {THREAT_LEVEL[process_info['threat_level']]}, "
                            f"Action: {ACTION_LEVEL[action_level]}, "
                            f"Warning #{warnings[process_name]}" # Corrected warning count display
                        )

                        # Execute appropriate action
                        if action_level == 0:  # MONITOR
                            continue
                        elif action_level == 1:  # WARN
                            # Just log it, we've already done that
                            pass
                        elif action_level == 2:  # SOFT_KILL
                            logging.warning(f"Attempting soft kill of {process_name} (PID: {pid})")
                            if kill_process(pid, force=False):
                                logging.info(f"Successfully soft-killed {process_name} (PID: {pid})")
                                # We don't record resurrection yet, only if it comes back
                            else:
                                logging.error(f"Failed to soft-kill {process_name} (PID: {pid})")
                        elif action_level == 3:  # FORCE_KILL
                            logging.warning(f"Attempting force kill of {process_name} (PID: {pid})")
                            if kill_process(pid, force=True):
                                logging.info(f"Successfully force-killed {process_name} (PID: {pid})")
                                # We don't record resurrection yet, only if it comes back
                            else:
                                logging.error(f"Failed to force-kill {process_name} (PID: {pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logging.error(f"Error processing process {pid}: {e}")


            # Check for disappeared processes (potential kills or normal exits)
            disappeared = previous_pids - current_pids
            if disappeared:
                for pid in disappeared:
                     # If a process we had in our repository disappeared
                     if pid in process_repository:
                         process_name = process_repository[pid]["name"]
                         threat_level = process_repository[pid]["threat_level"]
                         db_id = process_repository[pid]["db_id"]

                         # If it was a suspicious process that disappeared, it might have been killed or exited
                         if threat_level > 0:
                              # Check if it was killed by us (action_level > 1 implies a kill attempt)
                              # This is a simplification; a more robust check would track kill actions
                              # For now, assume if a suspicious process disappears, it might have been a successful termination or exit
                              logging.info(f"Suspicious process {process_name} (PID: {pid}) disappeared.")

                         # Reset warning count for the process name if it disappears
                         if process_name in warnings:
                             warnings[process_name] = 0

                         # If a critical process disappeared unexpectedly, log a warning
                         if threat_level == 0 and process_name.lower() not in ['system idle process', 'system', 'idle']:
                             logging.warning(f"Trusted process {process_name} (PID: {pid}) disappeared unexpectedly.")


            # Check for resurrected processes (processes that disappeared and came back with the same name/path/hash)
            # This check is more complex and requires comparing against historical data or a separate tracking mechanism
            # For simplicity in this iteration, we'll rely on the warning count incrementing if the same process name reappears.
            # A more advanced version would track process start times and compare against kill times.


            # Update previous pids for next iteration
            previous_pids = current_pids

            # Clean up process_repository - remove processes that are no longer running
            pids_to_remove = [pid for pid in process_repository if pid not in current_pids]
            for pid in pids_to_remove:
                 del process_repository[pid]

            # Sleep before next check
            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            logging.info("proc-wolf stopped by user.")
            break
        except Exception as e:
            logging.error(f"Error in main monitoring loop: {e}")
            time.sleep(CHECK_INTERVAL)

def nuke_process(pid, process_name, process_path):
    """Complete removal of a process and its artifacts"""
    # Always ask for confirmation before nuking
    if not confirm_nuke(process_name, pid):
        logging.info(f"Nuke operation for {process_name} (PID: {pid}) cancelled by user")
        return False

    log_prefix = f"NUKE: {process_name} (PID: {pid})"
    
    # ADDITIONAL SAFETY CHECKS - Prevent nuking critical processes
    process_name_lower = process_name.lower() if process_name else ""
    
    # List of processes that should NEVER be nuked under any circumstances
    absolutely_critical = [
        'explorer.exe', 'taskmgr.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
        'services.exe', 'smss.exe', 'wininit.exe', 'svchost.exe', 'dwm.exe',
        'procwolf', 'proc_wolf', 'python.exe'  # Our own processes
    ]
    
    # Check if this is a critical process
    for critical in absolutely_critical:
        if critical in process_name_lower:
            logging.error(f"{log_prefix} - ABORTING: Attempted to nuke critical system process!")
            return False
            
    # Check if this is potentially Explorer or a system process with a different path
    if process_path:
        if "\\windows\\" in process_path.lower():
            # Second confirmation for Windows system processes
            if not confirm_nuke_system_process(process_name, process_path, pid):
                logging.info(f"{log_prefix} - Nuke operation for system process cancelled by user")
                return False

    try:
        # 1. Kill the process first
        logging.warning(f"{log_prefix} - Killing process")
        if not kill_process(pid, force=True):
            logging.error(f"{log_prefix} - Failed to kill process")
            # Continue with cleanup attempt even if kill fails

        # Tracking variables for completion
        service_removed = False
        artifacts_removed = 0
        registry_keys_removed = 0

        # 2. If it's a service, disable and stop it
        if wmi_available:
            try:
                logging.info(f"{log_prefix} - Checking for services")
                wmi_obj = wmi.WMI()
                
                # Try to find service by process ID first
                services = wmi_obj.Win32_Service(ProcessId=pid)
                
                # FIXED: Be very careful when searching for services by name!
                if not services and process_name:
                    # Extract base name without extension
                    base_name = os.path.splitext(process_name)[0]
                    
                    # ONLY look for services with an EXACT name match
                    potential_services = wmi_obj.Win32_Service()
                    services = []
                    
                    for service in potential_services:
                        # Check for exact service name match, not partial
                        if service.Name.lower() == base_name.lower():
                            services.append(service)
                            logging.info(f"{log_prefix} - Found exact service name match: {service.Name}")

                if services:
                    # Process multiple services if found by name, but focus on one likely match
                    service = services[0]  # Take the first found service
                    service_name = service.Name

                    # Double-check that this isn't a critical system service
                    if service_name.lower() in ['wuauserv', 'windefend', 'bits', 'wscsvc', 'lanmanserver', 'schedule']:
                        logging.warning(f"{log_prefix} - ABORTING: Attempted to modify critical system service: {service_name}")
                        return False

                    try:
                        # Stop the service
                        logging.info(f"{log_prefix} - Stopping service: {service_name}")
                        # Check state before trying to stop
                        if service.State == "Running":
                             service.StopService()
                             # Give it a moment to stop
                             time.sleep(2)
                             # Re-fetch service state to confirm
                             services_after_stop = wmi_obj.Win32_Service(Name=service_name)
                             if services_after_stop and services_after_stop[0].State != "Stopped":
                                  logging.warning(f"{log_prefix} - Service {service_name} did not stop cleanly.")

                    except Exception as e:
                         logging.error(f"{log_prefix} - Error stopping service {service_name}: {e}")

                    try:
                        # Disable the service
                        logging.info(f"{log_prefix} - Disabling service: {service_name}")
                        # Check start mode before trying to disable
                        if service.StartMode != "Disabled":
                            result_disable = service.ChangeStartMode("Disabled")
                            if result_disable[0] == 0:  # 0 means success
                                logging.info(f"{log_prefix} - Disabled service: {service_name}")
                            else:
                                logging.warning(f"{log_prefix} - Failed to disable service {service_name}. Result code: {result_disable[0]}")
                        else:
                             logging.info(f"{log_prefix} - Service {service_name} is already disabled.")

                    except Exception as e:
                        logging.error(f"{log_prefix} - Error disabling service {service_name}: {e}")

                    try:
                        # Try to delete the service using sc delete
                        logging.info(f"{log_prefix} - Attempting to remove service: {service_name}")
                        subprocess.run(["sc", "delete", service_name], capture_output=True, text=True, check=False)
                        # Check result? subprocess.run returns CompletedProcess object
                        logging.info(f"{log_prefix} - 'sc delete {service_name}' command attempted.")

                        service_removed = True  # Assume success if the command ran
                    except Exception as e:
                         logging.error(f"{log_prefix} - Error removing service {service_name} with sc delete: {e}")

            except Exception as e:
                logging.error(f"{log_prefix} - Error handling service: {e}")

        # 3. Move the file to quarantine
        quarantine_success = False
        if process_path and os.path.exists(process_path):
            try:
                logging.info(f"{log_prefix} - Quarantining file: {process_path}")

                # Create quarantine dir if it doesn't exist
                quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
                if not os.path.exists(quarantine_dir):
                    os.makedirs(quarantine_dir)

                # Nuked files get a special extension
                quarantine_path = os.path.join(
                    quarantine_dir,
                    f"{os.path.basename(process_path)}.{int(time.time())}.nuked"
                )

                # Attempt to move the file
                os.rename(process_path, quarantine_path)
                logging.info(f"{log_prefix} - File moved to: {quarantine_path}")
                artifacts_removed += 1
                quarantine_success = True
            except Exception as e:
                logging.error(f"{log_prefix} - Failed to quarantine file by moving: {e}")

                # Try harder - use system commands to force deletion/move
                try:
                    logging.info(f"{log_prefix} - Attempting force move/deletion using system commands")
                    # Example: Using 'move' command
                    move_cmd = f'move /Y "{process_path}" "{quarantine_path}"'
                    result_move = subprocess.run(move_cmd, shell=True, capture_output=True, text=True, check=False)
                    if result_move.returncode == 0:
                         logging.info(f"{log_prefix} - File force-moved to: {quarantine_path}")
                         artifacts_removed += 1
                         quarantine_success = True
                    else:
                         # If move failed, try deletion as a last resort
                         logging.warning(f"{log_prefix} - Force move failed, attempting force deletion. Output: {result_move.stdout + result_move.stderr}")
                         del_cmd = f'del /F /Q "{process_path}"'
                         result_del = subprocess.run(del_cmd, shell=True, capture_output=True, text=True, check=False)
                         if result_del.returncode == 0:
                             logging.info(f"{log_prefix} - File force-deleted: {process_path}")
                             artifacts_removed += 1
                         else:
                             logging.error(f"{log_prefix} - Force deletion failed. Output: {result_del.stdout + result_del.stderr}")

                except Exception as sub_e:
                    logging.error(f"{log_prefix} - System command for file handling failed: {sub_e}")

        # 4. Check for related files in the same directory
        if process_path:
            try:
                base_dir = os.path.dirname(process_path)
                # Get base name without extension for broader matching
                base_name = os.path.splitext(os.path.basename(process_path))[0]

                logging.info(f"{log_prefix} - Checking for related files in: {base_dir}")

                # FIXED: Only look for files with EXACT name prefix, not contained substrings
                for file in os.listdir(base_dir):
                    full_file_path = os.path.join(base_dir, file)
                    # Only match files that START with our base name to avoid false positives
                    file_lower = file.lower()
                    if (os.path.isfile(full_file_path) and 
                        full_file_path.lower() != process_path.lower() and 
                        file_lower.startswith(base_name.lower() + ".")):  # Match exact prefix with extension delimiter
                        
                        try:
                            # Quarantine the related file
                            quarantine_path_related = os.path.join(
                                quarantine_dir,
                                f"{file}.{int(time.time())}.nuked_related"
                            )
                            os.rename(full_file_path, quarantine_path_related)
                            logging.info(f"{log_prefix} - Related file quarantined: {full_file_path}")
                            artifacts_removed += 1
                        except Exception as e:
                            logging.error(f"{log_prefix} - Failed to quarantine related file by moving {full_file_path}: {e}")
                            # Try force deletion if move fails
                            try:
                                logging.info(f"{log_prefix} - Attempting force deletion of related file: {full_file_path}")
                                del_cmd_related = f'del /F /Q "{full_file_path}"'
                                subprocess.run(del_cmd_related, shell=True, capture_output=True, text=True, check=False)
                                logging.info(f"{log_prefix} - Related file force-deleted: {full_file_path}")
                                artifacts_removed += 1
                            except Exception as sub_e:
                                logging.error(f"{log_prefix} - Force deletion of related file failed: {sub_e}")

            except Exception as e:
                logging.error(f"{log_prefix} - Error checking related files: {e}")

        # 5. Look for registry entries - MUCH MORE CAREFUL APPROACH
        try:
            logging.info(f"{log_prefix} - Cleaning registry entries")
            process_name_no_ext = os.path.splitext(process_name)[0].lower()
            
            # ADDITIONAL SAFETY CHECK - Skip registry cleaning for very short/common names
            if len(process_name_no_ext) < 4:
                logging.warning(f"{log_prefix} - Process name too short for safe registry cleaning: {process_name_no_ext}")
                registry_keys_removed = 0
            else:
                registry_roots_and_subkeys = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE"),
                    # REMOVED: winreg.HKEY_USERS - too dangerous to search all user profiles
                    (winreg.HKEY_CURRENT_CONFIG, r"Software")
                ]
    
                registry_keys_removed_count = 0
    
                # Helper to recursively delete keys
                def silent_reg_delete_key(hkey, subkey, key_name):
                    try:
                        winreg.DeleteKey(winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS), key_name)
                        return True
                    except FileNotFoundError:
                        return False
                    except Exception as e:
                        logging.warning(f"{log_prefix} - Could not delete registry key {subkey}\\{key_name}: {e}")
                        return False
    
                for root, subkey_path in registry_roots_and_subkeys:
                    try:
                        with winreg.OpenKey(root, subkey_path, 0, winreg.KEY_READ) as key:
                            i = 0
                            while True:
                                try:
                                    app_key_name = winreg.EnumKey(key, i)
                                    
                                    # FIXED: ONLY delete registry keys with EXACT name match
                                    # This is much safer than substring matching
                                    if app_key_name.lower() == process_name_no_ext:
                                        full_path = f"{subkey_path}\\{app_key_name}"
                                        logging.info(f"{log_prefix} - Found EXACT matching registry key: {full_path}")
    
                                        # Try to delete the key (recursive deletion if needed)
                                        try:
                                             winreg.DeleteKey(winreg.OpenKey(root, subkey_path, 0, winreg.KEY_ALL_ACCESS), app_key_name)
                                             logging.info(f"{log_prefix} - Deleted registry key: {full_path}")
                                             registry_keys_removed_count += 1
                                        except OSError as e:
                                             logging.warning(f"{log_prefix} - Direct deletion failed for {full_path}, recursive deletion required: {e}")
                                    
                                    i += 1
                                except OSError:
                                    # No more subkeys in this level
                                    break
                    except FileNotFoundError:
                         pass # Subkey path not found, not an error
                    except Exception as e:
                        logging.error(f"{log_prefix} - Error processing registry subkey {subkey_path}: {e}")
    
                logging.info(f"{log_prefix} - Removed {registry_keys_removed_count} registry keys.")
                registry_keys_removed = registry_keys_removed_count

        except Exception as e:
            logging.error(f"{log_prefix} - Error during registry cleaning phase: {e}")

        # 6. Record the nuke operation in the database
        nuke_success = quarantine_success # Consider nuke successful if the file was at least quarantined
        try:
            # Find process ID from database
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            # Get process ID from history if possible
            # Use name and path for more specific lookup
            cursor.execute(
                "SELECT id FROM process_history WHERE name = ? AND path = ?",
                (process_name, process_path)
            )

            result = cursor.fetchone()
            process_id = result[0] if result else None # Use None if not found

            conn.close()

            # Record the nuke operation
            db = Database(DB_FILE)
            db.record_nuke_operation(
                process_id,
                process_name,
                process_path,
                artifacts_removed,
                registry_keys_removed,
                service_removed,
                nuke_success  # Reflect if file quarantine was successful
            )

        except Exception as e:
            logging.error(f"{log_prefix} - Error recording nuke operation in database: {e}")

        if nuke_success:
             logging.info(f"{log_prefix} - Nuke operation completed with some success.")
        else:
             logging.warning(f"{log_prefix} - Nuke operation completed but file quarantine failed. Manual intervention may be required.")

        return nuke_success # Return success status based on file quarantine

    except Exception as e:
        logging.error(f"{log_prefix} - UNEXPECTED ERROR during nuke operation: {e}")
        # Record failure in database?
        return False # Indicate overall failure

# NEW FUNCTION - Add a special confirmation for system processes
def confirm_nuke_system_process(process_name, process_path, pid):
    """Show an even more serious confirmation dialog for system processes"""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()  # Hide the main window

        # Make sure the dialog appears on top
        root.attributes('-topmost', True)

        result = messagebox.askyesno(
            "CRITICAL SYSTEM PROCESS WARNING",
            f"⚠️ EXTREME CAUTION ⚠️\n\n"
            f"You are attempting to NUKE a possible system process:\n"
            f"'{process_name}' (PID: {pid})\n"
            f"Path: {process_path}\n\n"
            f"Removing system processes can cause PERMANENT SYSTEM DAMAGE\n"
            f"and render your computer UNBOOTABLE.\n\n"
            f"Are you ABSOLUTELY CERTAIN this is malware disguising\n"
            f"itself as a system process?",
            icon=messagebox.WARNING
        )

        root.destroy()
        return result
    except:
        # If GUI isn't available, fall back to console
        print("\n" + "!" * 80)
        print("⚠️ EXTREME DANGER: ATTEMPTING TO NUKE A SYSTEM PROCESS ⚠️")
        print("Removing system processes can cause PERMANENT SYSTEM DAMAGE")
        print("and render your computer UNBOOTABLE.")
        print("!" * 80)
        print(f"\nTarget: {process_name} (PID: {pid})")
        print(f"Path: {process_path}")

        confirmation = input("\nType 'I UNDERSTAND THE RISK' to confirm: ")
        return confirmation == "I UNDERSTAND THE RISK"

# === REPLACE monitor_processes FUNCTION ===
# This is the main monitoring loop that needs to be more conservative

def monitor_processes(db):
    """Main monitoring function"""
    logging.info(f"proc-wolf v{VERSION} started. Watching processes...")

    # Dictionary to track previous state
    previous_pids = set()

    # Add a cooldown tracking system to prevent too-frequent actions against the same process
    process_cooldowns = {}  # track {process_name: last_action_time}
    COOLDOWN_PERIOD = 300  # 5 minutes between actions for the same process name

    while True:
        try:
            # Get all current processes
            current_processes = {}
            current_pids = set()
            process_errors = 0  # Track errors for rate limiting

            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pid = proc.pid
                    current_pids.add(pid)

                    # Skip if we already know this process is trusted (check before getting full info)
                    if pid in process_repository and process_repository[pid]["trusted"]:
                         current_processes[pid] = process_repository[pid] # Keep in current processes
                         continue

                    # Get detailed information about the process
                    process_info = get_process_info(proc)
                    if not process_info:
                        continue

                    # Store in our current process dictionary
                    current_processes[pid] = process_info

                    # Add or update in database
                    db_id = db.add_or_update_process(process_info)
                    process_info["db_id"] = db_id

                    # Update our repository
                    process_repository[pid] = process_info


                    # Check if process requires action (only if not trusted)
                    if not process_info["trusted"]:
                        process_name = process_info["name"]

                        # ADDED: Check for cooldown period
                        current_time = time.time()
                        if process_name in process_cooldowns:
                            last_action_time = process_cooldowns[process_name]
                            if current_time - last_action_time < COOLDOWN_PERIOD:
                                logging.info(f"Process {process_name} (PID: {pid}) in cooldown period, monitoring only")
                                continue  # Skip to next process

                        # Check if this is an active application (user is using it)
                        if is_active_application(pid):
                            logging.info(f"Process {process_name} (PID: {pid}) appears suspicious but is currently active - monitoring only")
                            continue  # Skip to next process

                        # ADDED: Check for critical system processes one more time
                        critical_processes = ['explorer.exe', 'taskmgr.exe', 'winlogon.exe', 'services.exe']
                        if process_name.lower() in critical_processes:
                            logging.info(f"Process {process_name} (PID: {pid}) is a critical system process - monitoring only")
                            add_to_whitelist(process_name)  # Auto-whitelist critical processes
                            continue  # Skip to next process

                        # Initialize or increment warning count
                        if process_name not in warnings:
                            warnings[process_name] = 0
                        else:
                            warnings[process_name] += 1

                        # Determine action based on threat level and warnings
                        action_level = get_action_level(process_info["threat_level"], warnings[process_name])

                        # Log the detection
                        logging.warning(
                            f"Suspicious process: {process_name} (PID: {pid}), "
                            f"Threat: {THREAT_LEVEL[process_info['threat_level']]}, "
                            f"Action: {ACTION_LEVEL[action_level]}, "
                            f"Warning #{warnings[process_name]}"
                        )

                        # Execute appropriate action
                        if action_level == 0:  # MONITOR
                            continue
                        elif action_level == 1:  # WARN
                            # Just log it, we've already done that
                            # ADDED: Update cooldown time even for warnings
                            process_cooldowns[process_name] = current_time
                            pass
                        elif action_level == 2:  # SOFT_KILL
                            # ADDED: Extra check for system processes
                            if process_info['path'] and "\\windows\\" in process_info['path'].lower():
                                logging.warning(f"Not taking action on potential system process: {process_name} (PID: {pid})")
                                continue  # Skip to next process
                                
                            logging.warning(f"Attempting soft kill of {process_name} (PID: {pid})")
                            # ADDED: Update cooldown time before attempting kill
                            process_cooldowns[process_name] = current_time
                            
                            if kill_process(pid, force=False):
                                logging.info(f"Successfully soft-killed {process_name} (PID: {pid})")
                                # We don't record resurrection yet, only if it comes back
                            else:
                                logging.error(f"Failed to soft-kill {process_name} (PID: {pid})")
                        elif action_level == 3:  # FORCE_KILL
                            # ADDED: Extra check for system processes
                            if process_info['path'] and "\\windows\\" in process_info['path'].lower():
                                logging.warning(f"Not taking action on potential system process: {process_name} (PID: {pid})")
                                continue  # Skip to next process
                                
                            logging.warning(f"Attempting force kill of {process_name} (PID: {pid})")
                            # ADDED: Update cooldown time before attempting kill
                            process_cooldowns[process_name] = current_time
                            
                            if kill_process(pid, force=True):
                                logging.info(f"Successfully force-killed {process_name} (PID: {pid})")
                                # We don't record resurrection yet, only if it comes back
                            else:
                                logging.error(f"Failed to force-kill {process_name} (PID: {pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    process_errors += 1
                    # Rate limit error logging to prevent log spam
                    if process_errors <= 5:  # Only log the first 5 errors
                        logging.error(f"Error processing process {pid}: {e}")


            # Check for disappeared processes (potential kills or normal exits)
            disappeared = previous_pids - current_pids
            if disappeared:
                for pid in disappeared:
                     # If a process we had in our repository disappeared
                     if pid in process_repository:
                         process_name = process_repository[pid]["name"]
                         threat_level = process_repository[pid]["threat_level"]
                         db_id = process_repository[pid]["db_id"]

                         # If it was a suspicious process that disappeared, it might have been killed or exited
                         if threat_level > 0:
                              # Check if it was killed by us (action_level > 1 implies a kill attempt)
                              # This is a simplification; a more robust check would track kill actions
                              # For now, assume if a suspicious process disappears, it might have been a successful termination or exit
                              logging.info(f"Suspicious process {process_name} (PID: {pid}) disappeared.")

                         # Reset warning count for the process name if it disappears
                         if process_name in warnings:
                             warnings[process_name] = 0

                         # If a critical process disappeared unexpectedly, log a warning
                         if threat_level == 0 and process_name.lower() not in ['system idle process', 'system', 'idle']:
                             logging.warning(f"Trusted process {process_name} (PID: {pid}) disappeared unexpectedly.")


            # Update previous pids for next iteration
            previous_pids = current_pids

            # Clean up process_repository - remove processes that are no longer running
            pids_to_remove = [pid for pid in process_repository if pid not in current_pids]
            for pid in pids_to_remove:
                 del process_repository[pid]

            # Sleep before next check
            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            logging.info("proc-wolf stopped by user.")
            break
        except Exception as e:
            logging.error(f"Error in main monitoring loop: {e}")
            time.sleep(CHECK_INTERVAL)

def debug_process_detection(process_name, process_path, threat_level):
    """Special debug function to log process detection details"""
    with open("proc-wolf-debug.log", "a") as f:
        f.write(f"[{datetime.now()}] PROCESS: {process_name}, PATH: {process_path}, THREAT: {threat_level}\n")
        
        # Check critical lists
        in_system_critical = process_name.lower() in [x.lower() for x in SYSTEM_CRITICAL]
        is_trusted = is_whitelisted(process_name, process_path)
        
        f.write(f"  In SYSTEM_CRITICAL: {in_system_critical}\n")
        f.write(f"  In Whitelist: {is_trusted}\n")
        
        # Write stack trace to see the call chain
        import traceback
        f.write("  Call stack:\n")
        for line in traceback.format_stack()[:-1]:  # Exclude this function call
            f.write(f"    {line.strip()}\n")
        f.write("\n")

def main():
    """Main entry point"""
    # Check for administrative privileges
    if not is_admin():
        logging.warning("proc-wolf is not running with administrator privileges. Some features may not work.")

    logging.info(f"Starting proc-wolf v{VERSION}...")
    logging.info(f"System: {platform.system()} {platform.version()}")
    logging.info(f"Python: {platform.python_version()}")

    # Initialize database
    db = init_database()

    # Start monitoring processes
    try:
        monitor_processes(db)
    except KeyboardInterrupt:
        logging.info("proc-wolf stopped by user.")
    except Exception as e:
         logging.critical(f"Critical error in main execution: {e}")


if __name__ == "__main__":
    main()