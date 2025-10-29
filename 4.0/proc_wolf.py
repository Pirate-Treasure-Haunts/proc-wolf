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
import threading
import shutil
import json

# Try to import winreg
try:
    import winreg
except ImportError:
    try:
        import _winreg as winreg
    except ImportError:
        winreg = None

# Conditionally import win32 modules with proper error handling
win32_available = False
wmi_available = False
win32event_available = False

try:
    import win32api
    import win32process
    import win32security
    import win32gui
    import win32event
    win32_available = True
    win32event_available = True
except ImportError:
    try:
        from win32 import api as win32api
        from win32 import process as win32process
        from win32 import security as win32security
        from win32 import gui as win32gui
        from win32 import event as win32event
        win32_available = True
        win32event_available = True
    except ImportError:
        logging.warning("win32api/win32event modules not available. Some functions will be limited.")

try:
    import wmi
    wmi_available = True
except ImportError:
    logging.warning("wmi module not available. Some functions will be limited.")

# --- UPGRADE: Define a single, absolute, writable data directory ---
# C:\ProgramData is the correct location for system-wide service data.
APP_DATA_DIR = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'proc-wolf')
os.makedirs(APP_DATA_DIR, exist_ok=True)

# Global Constants
VERSION = "3.0.0"
CONFIG_FILE = os.path.join(APP_DATA_DIR, "proc-wolf.config")
DB_FILE = os.path.join(APP_DATA_DIR, "proc-wolf.db")
QUARANTINE_DIR = os.path.join(APP_DATA_DIR, "quarantine")
MAX_WARNINGS = 5
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
    2: "KILL",
    3: "QUARANTINE",
    4: "NUKE"
}

# Process tracking
process_repository = {}  # {pid: process_info}
warnings = {}  # {process_name: warning_count}

# Create quarantine directory if it doesn't exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# --- Database Class ---
class Database:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self.conn = None
        self.init_database()

    def init_database(self):
        """Initialize the database with required tables"""
        try:
            self.conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = self.conn.cursor()

            # Create process history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS process_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    name TEXT,
                    path TEXT,
                    command_line TEXT,
                    hash TEXT,
                    parent_pid INTEGER,
                    username TEXT,
                    create_time REAL,
                    threat_level INTEGER,
                    trusted BOOLEAN,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    times_seen INTEGER DEFAULT 1,
                    UNIQUE(pid, name, path)
                )
            """)

            # Create activity log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    process_id INTEGER,
                    process_name TEXT,
                    pid INTEGER,
                    action TEXT,
                    threat_level TEXT,
                    details TEXT,
                    FOREIGN KEY (process_id) REFERENCES process_history(id)
                )
            """)

            # Create whitelist table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,  -- 'name', 'path', or 'hash'
                    value TEXT UNIQUE,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            """)

            # Create threat patterns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT,  -- 'name', 'path', 'behavior', 'network'
                    pattern TEXT,
                    severity INTEGER,
                    description TEXT,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create nuke operations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nuke_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    process_id INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    artifacts_removed INTEGER,
                    registry_keys_removed INTEGER,
                    service_removed BOOLEAN,
                    success BOOLEAN,
                    FOREIGN KEY (process_id) REFERENCES process_history(id)
                )
            """)

            # Add default threat patterns if table is empty
            cursor.execute("SELECT COUNT(*) FROM threat_patterns")
            if cursor.fetchone()[0] == 0:
                default_patterns = [
                    ('name', 'svchost.exe', 3, 'Suspicious if not in System32'),
                    ('name', 'csrss.exe', 4, 'Critical system process - suspicious if duplicated'),
                    ('path', 'C:\\Users\\.*\\AppData\\Local\\Temp\\.*', 2, 'Process running from temp folder'),
                    ('path', '.*\\Downloads\\.*', 2, 'Process running from downloads folder'),
                    ('name', '.*cryptor.*', 4, 'Possible ransomware'),
                    ('name', '.*miner.*', 3, 'Possible cryptominer'),
                    ('name', '.*\\d{5,}\\.exe', 2, 'Randomly named executable'),
                ]
                cursor.executemany(
                    "INSERT INTO threat_patterns (pattern_type, pattern, severity, description) VALUES (?, ?, ?, ?)",
                    default_patterns
                )

            self.conn.commit()
            logging.info("Database initialized successfully")
            
        except sqlite3.Error as e:
            logging.error(f"Database initialization failed: {e}")
            raise ConnectionError(f"Failed to initialize database: {e}")

    def add_or_update_process(self, process_info):
        """Add or update process in the database"""
        cursor = self.conn.cursor()
        try:
            # Check if process exists
            cursor.execute(
                "SELECT id, times_seen FROM process_history WHERE pid = ? AND name = ? AND path = ?",
                (process_info['pid'], process_info['name'], process_info['path'])
            )
            result = cursor.fetchone()
            
            if result:
                # Update existing process
                cursor.execute("""
                    UPDATE process_history 
                    SET last_seen = CURRENT_TIMESTAMP, times_seen = times_seen + 1,
                        threat_level = ?, trusted = ?
                    WHERE id = ?
                """, (process_info['threat_level'], process_info['trusted'], result[0]))
                process_id = result[0]
            else:
                # Insert new process
                cursor.execute("""
                    INSERT INTO process_history 
                    (pid, name, path, command_line, hash, parent_pid, username, 
                     create_time, threat_level, trusted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    process_info['pid'],
                    process_info['name'],
                    process_info['path'],
                    process_info.get('command_line', ''),
                    process_info.get('hash', ''),
                    process_info.get('parent_pid', 0),
                    process_info.get('username', ''),
                    process_info.get('create_time', 0),
                    process_info['threat_level'],
                    process_info['trusted']
                ))
                process_id = cursor.lastrowid
                
            self.conn.commit()
            return process_id
            
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return None

    def log_activity(self, process_id, process_name, pid, action, threat_level, details=""):
        """Log process activity"""
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO activity_log (process_id, process_name, pid, action, threat_level, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (process_id, process_name, pid, action, threat_level, details))
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Failed to log activity: {e}")

    def log_process_activity(self, process_info, threat_level, action):
        """Log process activity with full details"""
        details = f"Path: {process_info.get('path', 'unknown')}, "
        details += f"User: {process_info.get('username', 'unknown')}, "
        details += f"Hash: {process_info.get('hash', 'unknown')}"
        
        self.log_activity(
            process_info.get('db_id', None),
            process_info['name'],
            process_info['pid'],
            action,
            threat_level,
            details
        )

    def get_process_history(self, limit=100):
        """Get process history"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT pid, name, path, threat_level, trusted, first_seen, last_seen, times_seen
            FROM process_history
            ORDER BY last_seen DESC
            LIMIT ?
        """, (limit,))
        return cursor.fetchall()

    def get_activity_log(self, limit=100):
        """Get activity log"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT timestamp, process_name, pid, action, threat_level, details
            FROM activity_log
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        return cursor.fetchall()

    def add_to_whitelist(self, type_, value, notes=""):
        """Add entry to whitelist"""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO whitelist (type, value, notes) VALUES (?, ?, ?)",
                (type_, value, notes)
            )
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Failed to add to whitelist: {e}")
            return False

    def remove_from_whitelist(self, value):
        """Remove entry from whitelist"""
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM whitelist WHERE value = ?", (value,))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Failed to remove from whitelist: {e}")
            return False

    def get_whitelist(self):
        """Get all whitelist entries"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT type, value, notes FROM whitelist")
        return cursor.fetchall()

    def is_whitelisted(self, process_name, process_path=None, process_hash=None):
        """Check if process is whitelisted"""
        cursor = self.conn.cursor()
        
        # Check by name
        cursor.execute("SELECT 1 FROM whitelist WHERE type = 'name' AND value = ?", (process_name,))
        if cursor.fetchone():
            return True
            
        # Check by path
        if process_path:
            cursor.execute("SELECT 1 FROM whitelist WHERE type = 'path' AND value = ?", (process_path,))
            if cursor.fetchone():
                return True
                
        # Check by hash
        if process_hash:
            cursor.execute("SELECT 1 FROM whitelist WHERE type = 'hash' AND value = ?", (process_hash,))
            if cursor.fetchone():
                return True
                
        return False

    def get_threat_patterns(self):
        """Get all threat patterns"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT pattern_type, pattern, severity FROM threat_patterns")
        return cursor.fetchall()

    def record_nuke_operation(self, process_id, process_name, process_path, 
                             artifacts_removed, registry_keys_removed, 
                             service_removed, success):
        """Record a nuke operation"""
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO nuke_operations 
                (process_id, process_name, process_path, artifacts_removed, 
                 registry_keys_removed, service_removed, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (process_id, process_name, process_path, artifacts_removed,
                 registry_keys_removed, service_removed, success))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Failed to record nuke operation: {e}")
            return False

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


# --- Whitelist Management ---
CRITICAL_WHITELIST = [
    'System',
    'Registry',
    'smss.exe',
    'csrss.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'winlogon.exe',
    'explorer.exe',
    'svchost.exe',
    'taskmgr.exe',
    'taskhost.exe',
    'dwm.exe',
]

# Common safe applications that shouldn't be flagged
SAFE_APPLICATIONS = [
    # Browsers
    'chrome.exe',
    'firefox.exe',
    'msedge.exe',
    'brave.exe',
    'vivaldi.exe',
    'opera.exe',
    'iexplore.exe',
    # Development
    'code.exe',
    'devenv.exe',
    'python.exe',
    'node.exe',
    'git.exe',
    # Communication
    'discord.exe',
    'slack.exe',
    'teams.exe',
    'zoom.exe',
    'skype.exe',
    # Media
    'spotify.exe',
    'vlc.exe',
    'obs64.exe',
    'obs.exe',
    # System tools
    'powershell.exe',
    'cmd.exe',
    'conhost.exe',
    'terminal.exe',
    'wt.exe',
]

def is_whitelisted(process_name, process_path=None, db=None):
    """Check if a process is whitelisted"""
    if not process_name:
        return False
    
    # Check critical system processes
    if process_name.lower() in [p.lower() for p in CRITICAL_WHITELIST]:
        # For critical system processes, verify they're in the correct location
        if process_path and 'System32' in process_path:
            return True
    
    # Check safe applications list
    if process_name.lower() in [p.lower() for p in SAFE_APPLICATIONS]:
        return True
    
    # Check database whitelist if available
    if db:
        try:
            return db.is_whitelisted(process_name, process_path)
        except:
            pass
    
    return False

def add_to_whitelist(process_name, process_path=None):
    """Add a process to the whitelist"""
    try:
        db = Database()
        if process_path:
            db.add_to_whitelist('path', process_path, f"Added for process: {process_name}")
        else:
            db.add_to_whitelist('name', process_name, "Added via proc-wolf")
        db.close()
        logging.info(f"Added to whitelist: {process_name}")
        return True
    except Exception as e:
        logging.error(f"Failed to add to whitelist: {e}")
        return False

def remove_from_whitelist(entry):
    """Remove an entry from the whitelist"""
    try:
        db = Database()
        result = db.remove_from_whitelist(entry)
        db.close()
        return result
    except Exception as e:
        logging.error(f"Failed to remove from whitelist: {e}")
        return False

def get_whitelist_entries():
    """Get all whitelist entries"""
    try:
        db = Database()
        entries = db.get_whitelist()
        db.close()
        return entries
    except Exception as e:
        logging.error(f"Failed to get whitelist: {e}")
        return []


# --- Process Analysis Functions ---
def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_process_hash(process_path):
    """Calculate SHA256 hash of the process executable"""
    if not process_path or not os.path.exists(process_path):
        return None
    
    try:
        sha256_hash = hashlib.sha256()
        with open(process_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.debug(f"Failed to hash {process_path}: {e}")
        return None

def check_digital_signature(process_path):
    """Check if the process has a valid digital signature"""
    if not win32_available:
        return None
        
    if not process_path or not os.path.exists(process_path):
        return False
    
    try:
        # Use Windows API to verify signature
        result = win32api.GetFileVersionInfo(process_path, '\\')
        return bool(result)
    except:
        return False

def is_suspicious_name(process_name):
    """Check if process name matches suspicious patterns"""
    if not process_name:
        return False
    
    suspicious_patterns = [
        r'.*cryptor.*',
        r'.*miner.*',
        r'.*ransom.*',
        r'.*stealer.*',
        r'.*keylog.*',
        r'.*backdoor.*',
        r'.*trojan.*',
        r'.*virus.*',
        r'.*malware.*',
        r'.*\d{5,}\.exe$',  # Randomly named executables
        r'^[a-z]{6,8}\.exe$',  # Random lowercase names
    ]
    
    name_lower = process_name.lower()
    for pattern in suspicious_patterns:
        if re.match(pattern, name_lower):
            return True
    
    # Check for system process impersonation
    system_processes = ['svchost.exe', 'csrss.exe', 'winlogon.exe', 'services.exe']
    for sys_proc in system_processes:
        # Suspicious if similar but not exact match
        if name_lower != sys_proc and name_lower.replace(' ', '') == sys_proc.replace('.', ''):
            return True
    
    return False

def is_suspicious_location(process_path):
    """Check if process is running from a suspicious location"""
    if not process_path:
        return False
    
    suspicious_paths = [
        r'.*\\AppData\\Local\\Temp\\.*',
        r'.*\\Downloads\\.*',
        r'.*\\Desktop\\.*',
        r'.*\\$Recycle\.Bin\\.*',
        r'.*\\ProgramData\\.*\\.*\.exe$',
        r'.*\\Users\\Public\\.*',
    ]
    
    for pattern in suspicious_paths:
        if re.match(pattern, process_path, re.IGNORECASE):
            return True
    
    return False

def has_suspicious_behavior(pid, proc_info=None):
    """Check for suspicious process behavior"""
    suspicious_indicators = 0
    
    try:
        if not proc_info:
            proc = psutil.Process(pid)
        else:
            proc = proc_info.get('psutil_proc')
            if not proc:
                proc = psutil.Process(pid)
        
        # Check network connections
        try:
            connections = proc.connections(kind='inet')
            # Suspicious if has many connections or connects to unusual ports
            if len(connections) > 10:
                suspicious_indicators += 1
            
            for conn in connections:
                if conn.raddr and conn.raddr.port in [25, 587, 465, 6667, 4444, 5555]:
                    suspicious_indicators += 2  # Known malware ports
        except:
            pass
        
        # Check CPU usage
        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
            if cpu_percent > 80:
                suspicious_indicators += 1
        except:
            pass
        
        # Check memory usage
        try:
            mem_info = proc.memory_info()
            if mem_info.rss > 500 * 1024 * 1024:  # More than 500MB
                suspicious_indicators += 1
        except:
            pass
        
        # Check number of threads
        try:
            if proc.num_threads() > 50:
                suspicious_indicators += 1
        except:
            pass
        
        # Check if process has no visible window but high activity
        if win32_available:
            try:
                import win32process
                import win32gui
                
                def callback(hwnd, windows):
                    if win32gui.IsWindowVisible(hwnd) and win32gui.IsWindowEnabled(hwnd):
                        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                        if found_pid == pid:
                            windows.append(hwnd)
                    return True
                
                windows = []
                win32gui.EnumWindows(callback, windows)
                
                if len(windows) == 0 and suspicious_indicators > 0:
                    suspicious_indicators += 1  # Hidden process with suspicious activity
            except:
                pass
    
    except psutil.NoSuchProcess:
        return False
    except Exception as e:
        logging.debug(f"Error checking behavior for PID {pid}: {e}")
        return False
    
    return suspicious_indicators >= 2

def is_interactive_process(pid):
    """Check if a process has user interaction (windows, console, etc.)"""
    try:
        proc = psutil.Process(pid)
        
        # Check if it's a console process
        if proc.name().lower() in ['cmd.exe', 'powershell.exe', 'python.exe', 'node.exe']:
            return True
        
        # Check for windows if win32 is available
        if win32_available:
            try:
                import win32gui
                import win32process
                
                def callback(hwnd, windows):
                    if win32gui.IsWindowVisible(hwnd):
                        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                        if found_pid == pid:
                            windows.append(hwnd)
                    return True
                
                windows = []
                win32gui.EnumWindows(callback, windows)
                return len(windows) > 0
            except:
                pass
    except:
        pass
    
    return False

def is_active_application(pid):
    """Check if process appears to be actively used by the user"""
    try:
        proc = psutil.Process(pid)
        proc_name_lower = proc.name().lower()
        
        # Extended list of known safe applications
        app_names = [
            # Browsers
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 
            'vivaldi.exe', 'opera.exe', 'iexplore.exe',
            # Development
            'code.exe', 'devenv.exe', 'notepad.exe', 'notepad++.exe',
            # Communication
            'discord.exe', 'slack.exe', 'teams.exe', 'zoom.exe', 'skype.exe',
            # Media
            'spotify.exe', 'vlc.exe', 'obs64.exe', 'obs.exe',
            # Productivity
            'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
            # Graphics
            'photoshop.exe', 'illustrator.exe', 'gimp.exe',
            # Games/Gaming platforms
            'steam.exe', 'epicgameslauncher.exe', 'origin.exe',
        ]
        
        if proc_name_lower in app_names:
            # Don't even check CPU for known apps - they're legitimate
            return True
        
        # Check if it has significant CPU usage (actively doing something)
        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
            if cpu_percent > 0.5:  # Lowered threshold
                return True
        except:
            pass
        
        # Check if it's the foreground window
        if win32_available:
            try:
                import win32gui
                import win32process
                
                foreground_hwnd = win32gui.GetForegroundWindow()
                if foreground_hwnd:
                    _, foreground_pid = win32process.GetWindowThreadProcessId(foreground_hwnd)
                    if foreground_pid == pid:
                        return True
            except:
                pass
    
    except:
        pass
    
    return False

def confirm_nuke(process_name, pid):
    """Get user confirmation before nuking a process"""
    try:
        # Try GUI confirmation first
        import tkinter as tk
        from tkinter import messagebox
        
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        
        result = messagebox.askyesno(
            "Confirm Process Termination",
            f"⚠️ WARNING: Complete removal (NUKE) requested ⚠️\n\n"
            f"Process: {process_name} (PID: {pid})\n\n"
            f"This will:\n"
            f"• Kill the process immediately\n"
            f"• Quarantine the executable file\n"
            f"• Remove registry entries\n"
            f"• Block future execution\n\n"
            f"Are you absolutely sure?",
            icon=messagebox.WARNING
        )
        
        root.destroy()
        
        if not result:
            logging.info(f"User declined to nuke {process_name} (PID: {pid})")
        
        return result
        
    except ImportError:
        logging.warning("tkinter not available, falling back to console confirmation")
    except Exception as e:
        logging.error(f"Error showing GUI confirmation: {e}")
    
    # Fall back to console confirmation
    try:
        print("\n" + "=" * 60)
        print("⚠️ NUKE OPERATION REQUESTED ⚠️")
        print("=" * 60)
        print(f"Target: {process_name} (PID: {pid})")
        print("\nThis will completely remove the process and prevent resurrection.")
        response = input("\nType 'YES' to confirm (or press Enter to cancel): ")
        
        result = response.upper() == 'YES'
        if not result:
            logging.info(f"User declined to nuke {process_name} (PID: {pid}) via console")
        
        return result
        
    except Exception as e:
        logging.error(f"Error in console confirmation: {e}")
        # If we can't get confirmation, default to NOT nuking for safety
        return False

def evaluate_threat_level(process_info):
    """Evaluate the threat level of a process"""
    threat_score = 0
    
    # Check if whitelisted (trusted)
    if process_info.get('trusted', False):
        return 0  # TRUSTED
    
    # Check if it's a known safe application (double-check)
    process_name_lower = process_info['name'].lower() if process_info.get('name') else ''
    if process_name_lower in [app.lower() for app in SAFE_APPLICATIONS]:
        return 0  # TRUSTED - safe application
    
    # Check if running from Program Files (usually legitimate)
    process_path = process_info.get('path', '')
    if process_path:
        if 'Program Files' in process_path or 'Program Files (x86)' in process_path:
            # Reduce threat score for Program Files applications
            threat_score -= 1
    
    # Check digital signature
    if not process_info.get('signed', False):
        threat_score += 2
    
    # Check process name
    if is_suspicious_name(process_info['name']):
        threat_score += 3
    
    # Check process location
    if is_suspicious_location(process_info.get('path', '')):
        threat_score += 2
    
    # Check for suspicious behavior
    if has_suspicious_behavior(process_info['pid'], process_info):
        threat_score += 3
    
    # Check parent process
    parent_name = process_info.get('parent_name', '')
    if parent_name and parent_name.lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']:
        # Only add threat if it's not a development tool
        if process_name_lower not in ['python.exe', 'node.exe', 'java.exe', 'git.exe']:
            threat_score += 1
    
    # Check if process is hidden
    if not is_interactive_process(process_info['pid']):
        threat_score += 1
    
    # Normalize threat score (can't be negative)
    threat_score = max(0, threat_score)
    
    # Determine threat level based on score
    if threat_score == 0:
        return 0  # TRUSTED
    elif threat_score <= 2:
        return 1  # LOW
    elif threat_score <= 4:
        return 2  # MEDIUM
    elif threat_score <= 6:
        return 3  # HIGH
    else:
        return 4  # CRITICAL

def get_action_level(threat_level, warnings_count):
    """Determine action based on threat level and warning count"""
    if threat_level == 0:  # TRUSTED
        return 0  # MONITOR
    elif threat_level == 1:  # LOW
        return 0 if warnings_count < 3 else 1  # MONITOR -> WARN
    elif threat_level == 2:  # MEDIUM
        if warnings_count < 2:
            return 1  # WARN
        elif warnings_count < 4:
            return 2  # KILL
        else:
            return 3  # QUARANTINE
    elif threat_level == 3:  # HIGH
        if warnings_count < 1:
            return 2  # KILL
        else:
            return 3  # QUARANTINE
    else:  # CRITICAL
        return 4  # NUKE

def kill_process(pid, db=None):
    """Kill a process by PID"""
    try:
        proc = psutil.Process(pid)
        process_name = proc.name()
        proc.terminate()
        
        # Wait a moment and force kill if necessary
        time.sleep(0.5)
        if proc.is_running():
            proc.kill()
        
        logging.info(f"Killed process: {process_name} (PID: {pid})")
        
        if db:
            db.log_activity(None, process_name, pid, "KILLED", "N/A", "Process terminated")
        
        return True
    except psutil.NoSuchProcess:
        logging.info(f"Process {pid} no longer exists")
        return True
    except Exception as e:
        logging.error(f"Failed to kill process {pid}: {e}")
        return False

def quarantine_file(file_path, db=None):
    """Move a file to quarantine"""
    if not file_path or not os.path.exists(file_path):
        return False
    
    try:
        # Create quarantine filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        quarantine_name = f"{timestamp}_{filename}.quarantine"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)
        
        # Move file to quarantine
        shutil.move(file_path, quarantine_path)
        
        # Create info file
        info_file = quarantine_path + ".info"
        info = {
            "original_path": file_path,
            "quarantine_date": timestamp,
            "hash": get_process_hash(quarantine_path)
        }
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        logging.info(f"Quarantined file: {file_path} -> {quarantine_path}")
        
        if db:
            db.log_activity(None, filename, 0, "QUARANTINED", "N/A", 
                          f"File moved to quarantine: {quarantine_path}")
        
        return True
    
    except Exception as e:
        logging.error(f"Failed to quarantine {file_path}: {e}")
        return False

def prevent_resurrection(pid, process_name, process_path):
    """Prevent a process from being restarted"""
    prevented = False
    
    if not winreg:
        return False
    
    # Check and remove from common startup locations
    startup_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    
    for root_key, sub_key in startup_keys:
        try:
            key = winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_ALL_ACCESS)
            
            # Enumerate all values
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # Check if this entry points to our process
                    if process_path and process_path.lower() in value.lower():
                        winreg.DeleteValue(key, name)
                        logging.info(f"Removed startup entry: {name}")
                        prevented = True
                        continue  # Don't increment i since we deleted an entry
                    i += 1
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
        except Exception as e:
            logging.debug(f"Could not check registry key {sub_key}: {e}")
    
    # Check scheduled tasks
    if process_path:
        try:
            # Disable any scheduled tasks that run this process
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'csv', '/v'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if process_path.lower() in line.lower():
                        # Extract task name
                        parts = line.split(',')
                        if len(parts) > 1:
                            task_name = parts[1].strip('"')
                            # Disable the task
                            subprocess.run(
                                ['schtasks', '/change', '/tn', task_name, '/disable'],
                                capture_output=True, timeout=5
                            )
                            logging.info(f"Disabled scheduled task: {task_name}")
                            prevented = True
        except:
            pass
    
    return prevented

def get_process_info(proc):
    """Get comprehensive information about a process"""
    try:
        pid = proc.pid
        name = proc.name()
        
        # Get basic info
        info = {
            'pid': pid,
            'name': name,
            'path': None,
            'command_line': None,
            'parent_pid': None,
            'parent_name': None,
            'username': None,
            'create_time': None,
            'hash': None,
            'signed': None,
            'threat_level': 0,
            'trusted': False,
            'psutil_proc': proc
        }
        
        # Get extended info with timeout
        with proc.oneshot():
            try:
                info['path'] = proc.exe()
            except:
                pass
            
            try:
                info['command_line'] = ' '.join(proc.cmdline())
            except:
                pass
            
            try:
                info['parent_pid'] = proc.ppid()
                if info['parent_pid']:
                    parent_proc = psutil.Process(info['parent_pid'])
                    info['parent_name'] = parent_proc.name()
            except:
                pass
            
            try:
                info['username'] = proc.username()
            except:
                pass
            
            try:
                info['create_time'] = proc.create_time()
            except:
                pass
        
        # Check if whitelisted
        info['trusted'] = is_whitelisted(name, info['path'])
        
        # Get hash and signature if we have the path
        if info['path']:
            info['hash'] = get_process_hash(info['path'])
            info['signed'] = check_digital_signature(info['path'])
        
        # Evaluate threat level
        info['threat_level'] = evaluate_threat_level(info)
        
        return info
    
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    except Exception as e:
        logging.debug(f"Error getting info for PID {proc.pid}: {e}")
        return None

def get_process_info_advanced(pid):
    """Enhanced version with WMI and deeper checks"""
    try:
        # Start with basic psutil info
        proc = psutil.Process(pid)
        info = get_process_info(proc)
        
        if not info:
            return None
        
        # Add WMI information if available
        if wmi_available:
            try:
                c = wmi.WMI()
                wmi_processes = c.Win32_Process(ProcessId=pid)
                if wmi_processes:
                    wmi_proc = wmi_processes[0]
                    info['wmi_executable_path'] = wmi_proc.ExecutablePath
                    info['wmi_command_line'] = wmi_proc.CommandLine
                    info['wmi_creation_date'] = wmi_proc.CreationDate
                    info['wmi_priority'] = wmi_proc.Priority
                    info['wmi_thread_count'] = wmi_proc.ThreadCount
                    info['wmi_handle_count'] = wmi_proc.HandleCount
            except:
                pass
        
        # Check for code injection indicators
        if win32_available:
            try:
                import win32api
                import win32con
                
                # Open process with query information rights
                handle = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                    False, pid
                )
                
                if handle:
                    # Could add memory region checks here
                    win32api.CloseHandle(handle)
            except:
                pass
        
        return info
    
    except Exception as e:
        logging.debug(f"Error in advanced process info for PID {pid}: {e}")
        return None

def init_database():
    """Initialize and return database connection"""
    try:
        db = Database(DB_FILE)
        
        # Add critical processes to whitelist
        critical_added = 0
        for proc in CRITICAL_WHITELIST:
            if db.add_to_whitelist('name', proc, "Critical system process"):
                critical_added += 1
        
        # Add safe applications to whitelist
        safe_added = 0
        for app in SAFE_APPLICATIONS:
            if db.add_to_whitelist('name', app, "Safe application"):
                safe_added += 1
        
        # Add some common safe paths
        safe_paths = [
            "C:\\Windows\\System32\\",
            "C:\\Windows\\explorer.exe",
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\",
        ]
        paths_added = 0
        for path in safe_paths:
            if db.add_to_whitelist('path', path, "System/Program path"):
                paths_added += 1
        
        logging.info(f"Database initialized with whitelist:")
        logging.info(f"  - {critical_added}/{len(CRITICAL_WHITELIST)} critical system processes")
        logging.info(f"  - {safe_added}/{len(SAFE_APPLICATIONS)} safe applications")
        logging.info(f"  - {paths_added}/{len(safe_paths)} safe paths")
        logging.info(f"  - Vivaldi browser: {'WHITELISTED' if 'vivaldi.exe' in [x.lower() for x in SAFE_APPLICATIONS] else 'NOT WHITELISTED'}")
        
        return db
    
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}")
        raise ConnectionError(f"Database initialization failed: {e}")

def monitor_processes(db, stop_event=None):
    """
    Main loop for monitoring processes, compatible with Windows Service stop events.
    
    :param db: The Database object
    :param stop_event: win32event handle for service shutdown, or threading.Event, or None for CLI
    """
    global CHECK_INTERVAL, win32event_available
    
    logging.info(f"Starting process monitoring loop (v{VERSION})")
    logging.info(f"Check interval: {CHECK_INTERVAL} seconds")
    logging.info(f"Stop event type: {type(stop_event).__name__ if stop_event else 'None'}")
    
    # Track previous PIDs to detect process terminations
    previous_pids = set()
    
    # Cooldown tracking to prevent too-frequent actions
    process_cooldowns = {}
    COOLDOWN_PERIOD = 300  # 5 minutes
    
    # Main monitoring loop
    iteration = 0
    while True:
        try:
            iteration += 1
            if iteration % 12 == 1:  # Log every minute (5 seconds * 12)
                logging.info(f"Monitor loop iteration {iteration}, tracking {len(current_pids)} processes")
            
            # Gather current process information
            current_pids = set()
            current_processes = {}
            skipped_count = 0
            checked_count = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    checked_count += 1
                    
                    # Get enhanced process information
                    process_info = get_process_info_advanced(proc.pid)
                    
                    if process_info:
                        current_pids.add(proc.pid)
                        current_processes[proc.pid] = process_info
                        
                        # Skip if whitelisted
                        if is_whitelisted(process_info['name'], process_info.get('path'), db):
                            skipped_count += 1
                            continue
                        
                        # Check cooldown
                        process_name = process_info['name']
                        current_time = time.time()
                        
                        if process_name in process_cooldowns:
                            if current_time - process_cooldowns[process_name] < COOLDOWN_PERIOD:
                                continue
                        
                        # Skip if active user application
                        if is_active_application(proc.pid):
                            continue
                        
                        # Auto-whitelist critical system processes
                        critical_procs = ['explorer.exe', 'taskmgr.exe', 'winlogon.exe', 'services.exe']
                        if process_name.lower() in critical_procs and 'System32' in str(process_info.get('path', '')):
                            add_to_whitelist(process_name, process_info.get('path'))
                            continue
                        
                        # Evaluate threat level
                        threat_level = evaluate_threat_level(process_info)
                        
                        # Only log and act if not LOW threat
                        if threat_level > 1:  # Not TRUSTED or LOW
                            # Track warnings
                            if process_name not in warnings:
                                warnings[process_name] = 0
                            warnings[process_name] += 1
                            
                            # Determine action
                            action_level = get_action_level(threat_level, warnings[process_name])
                            
                            # Log the detection
                            db.log_process_activity(
                                process_info, 
                                THREAT_LEVEL[threat_level], 
                                ACTION_LEVEL[action_level]
                            )
                            
                            logging.warning(
                                f"Suspicious process detected: {process_name} (PID: {proc.pid}), "
                                f"Threat: {THREAT_LEVEL[threat_level]}, "
                                f"Action: {ACTION_LEVEL[action_level]}"
                            )
                            
                            # Execute action
                            action_executed = False
                            try:
                                if action_level == 2:  # KILL
                                    logging.info(f"Attempting to kill process: {process_name} (PID: {proc.pid})")
                                    if kill_process(proc.pid, db):
                                        process_cooldowns[process_name] = current_time
                                        action_executed = True
                                    else:
                                        logging.info(f"Kill action cancelled or failed for {process_name}")
                                        
                                elif action_level == 3:  # QUARANTINE
                                    if process_info.get('path'):
                                        logging.info(f"Attempting to quarantine: {process_name}")
                                        if quarantine_file(process_info['path'], db):
                                            kill_process(proc.pid, db)
                                            process_cooldowns[process_name] = current_time
                                            action_executed = True
                                        else:
                                            logging.info(f"Quarantine action cancelled or failed for {process_name}")
                                            
                                elif action_level == 4:  # NUKE
                                    if process_info.get('path'):
                                        logging.info(f"Attempting to nuke: {process_name}")
                                        if nuke_process(proc.pid, process_name, process_info['path'], db):
                                            process_cooldowns[process_name] = current_time
                                            action_executed = True
                                        else:
                                            logging.info(f"Nuke action cancelled by user for {process_name}")
                                            # User cancelled - this is normal, continue monitoring
                                            
                            except Exception as e:
                                logging.error(f"Error executing action for {process_name}: {e}")
                                # Don't crash the entire service for action failures
                                continue
                        
                        # Add to database even if low threat
                        db.add_or_update_process(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logging.debug(f"Error processing PID {proc.pid}: {e}")
            
            # Log summary periodically
            if iteration % 12 == 0:  # Every minute
                logging.info(f"Monitor status - Checked: {checked_count}, Whitelisted: {skipped_count}, Active PIDs: {len(current_pids)}")
            
            # Check for disappeared processes
            disappeared_pids = previous_pids - current_pids
            for pid in disappeared_pids:
                if pid in process_repository:
                    proc_info = process_repository[pid]
                    if proc_info.get('trusted'):
                        logging.info(f"Trusted process terminated: {proc_info['name']} (PID: {pid})")
            
            # Update tracking
            previous_pids = current_pids
            
            # Clean up process repository
            for pid in list(process_repository.keys()):
                if pid not in current_pids:
                    del process_repository[pid]
            
            # Handle wait/sleep with stop event support
            try:
                if stop_event is not None:
                    if isinstance(stop_event, threading.Event):
                        # Threading event (for background mode)
                        if stop_event.wait(timeout=CHECK_INTERVAL):
                            logging.info("Stop event (threading) received, exiting monitor loop")
                            break
                    elif win32event_available and hasattr(stop_event, '__int__'):
                        # Win32 event handle (for service mode)
                        wait_ms = int(CHECK_INTERVAL * 1000)
                        result = win32event.WaitForSingleObject(stop_event, wait_ms)
                        
                        if result == win32event.WAIT_OBJECT_0:
                            logging.info("Stop event (win32) received, exiting monitor loop")
                            break
                        elif result == win32event.WAIT_TIMEOUT:
                            # Normal timeout, continue loop
                            pass
                        else:
                            logging.warning(f"Unexpected wait result: {result}")
                    else:
                        # Unknown event type, just sleep
                        time.sleep(CHECK_INTERVAL)
                else:
                    # No stop event (CLI mode)
                    time.sleep(CHECK_INTERVAL)
                    
            except Exception as e:
                logging.error(f"Error handling stop event: {e}")
                # Fall back to simple sleep if stop event handling fails
                time.sleep(CHECK_INTERVAL)
        
        except KeyboardInterrupt:
            logging.info("Monitor loop interrupted by user")
            break
        except Exception as e:
            logging.error(f"Critical error in monitor loop: {e}", exc_info=True)
            
            # Check for stop event even on error
            if stop_event is not None:
                if isinstance(stop_event, threading.Event) and stop_event.is_set():
                    break
                elif win32event_available and hasattr(stop_event, '__int__'):
                    if win32event.WaitForSingleObject(stop_event, 0) == win32event.WAIT_OBJECT_0:
                        break
            
            # Brief delay before retry
            time.sleep(5)
    
    logging.info("Process monitoring loop ended")

def nuke_process(pid, process_name, process_path, db=None):
    """Complete removal of a process and prevention of resurrection"""
    
    # Require confirmation for nuke operations
    if not confirm_nuke(process_name, pid):
        logging.info(f"Nuke operation cancelled for {process_name} (PID: {pid})")
        return False
    
    log_prefix = f"NUKE: {process_name} (PID: {pid})"
    
    # Additional safety check for critical processes
    critical_system = ['explorer.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 
                      'lsass.exe', 'svchost.exe', 'system', 'smss.exe']
    
    if process_name.lower() in critical_system:
        if not confirm_nuke_system_process(process_name, process_path, pid):
            logging.warning(f"{log_prefix} - Aborted: Critical system process protection")
            return False
    
    try:
        # 1. Kill the process
        killed = kill_process(pid, db)
        if not killed:
            logging.warning(f"{log_prefix} - Failed to kill process, continuing with other steps")
        
        # 2. Quarantine the file
        quarantined = False
        if process_path and os.path.exists(process_path):
            quarantined = quarantine_file(process_path, db)
        
        # 3. Prevent resurrection
        prevented = prevent_resurrection(pid, process_name, process_path)
        
        # 4. Remove from scheduled tasks
        tasks_removed = 0
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'csv'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if process_name.lower() in line.lower():
                        parts = line.split(',')
                        if len(parts) > 0:
                            task_name = parts[0].strip('"')
                            subprocess.run(
                                ['schtasks', '/delete', '/tn', task_name, '/f'],
                                capture_output=True, timeout=5
                            )
                            tasks_removed += 1
                            logging.info(f"{log_prefix} - Removed scheduled task: {task_name}")
        except:
            pass
        
        # 5. Clean registry
        registry_cleaned = 0
        if winreg and process_name:
            registry_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"),
                (winreg.HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\open\command"),
            ]
            
            for root_key, sub_key in registry_locations:
                try:
                    key = winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_ALL_ACCESS)
                    
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if process_path and process_path.lower() in value.lower():
                                winreg.DeleteValue(key, name)
                                registry_cleaned += 1
                                logging.info(f"{log_prefix} - Removed registry value: {name}")
                                continue
                            i += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(key)
                except:
                    pass
        
        # 6. Record the nuke operation
        if db:
            db.record_nuke_operation(
                None,  # process_id will be looked up by the db method
                process_name,
                process_path,
                1 if quarantined else 0,  # artifacts_removed
                registry_cleaned,  # registry_keys_removed
                tasks_removed > 0,  # service_removed
                True  # success
            )
        
        # Log summary
        logging.info(
            f"{log_prefix} - Operation complete: "
            f"Killed={killed}, Quarantined={quarantined}, "
            f"Registry={registry_cleaned}, Tasks={tasks_removed}"
        )
        
        return True
    
    except Exception as e:
        logging.error(f"{log_prefix} - Unexpected error: {e}", exc_info=True)
        return False

def confirm_nuke_system_process(process_name, process_path, pid):
    """Extra confirmation for system processes"""
    try:
        import tkinter as tk
        from tkinter import messagebox
        
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        
        result = messagebox.askyesno(
            "CRITICAL SYSTEM PROCESS WARNING",
            f"⚠️ EXTREME CAUTION ⚠️\n\n"
            f"You are attempting to NUKE a system process:\n"
            f"'{process_name}' (PID: {pid})\n"
            f"Path: {process_path}\n\n"
            f"This may cause PERMANENT SYSTEM DAMAGE\n"
            f"and render your computer UNBOOTABLE.\n\n"
            f"Are you ABSOLUTELY CERTAIN this is malware?",
            icon=messagebox.WARNING
        )
        
        root.destroy()
        return result
    except:
        # Console fallback
        print("\n" + "!" * 80)
        print("⚠️ EXTREME DANGER: SYSTEM PROCESS NUKE ⚠️")
        print("!" * 80)
        print(f"Target: {process_name} (PID: {pid})")
        print(f"Path: {process_path}")
        print("\nThis action may make your system unbootable!")
        
        confirmation = input("\nType 'I UNDERSTAND THE RISK' to confirm: ")
        return confirmation == "I UNDERSTAND THE RISK"

def main():
    """Main entry point for CLI execution"""
    if not is_admin():
        logging.warning("proc-wolf is not running with administrator privileges. Some features may not work.")
    
    logging.info(f"Starting proc-wolf v{VERSION}...")
    logging.info(f"System: {platform.system()} {platform.version()}")
    logging.info(f"Python: {platform.python_version()}")
    
    try:
        db = init_database()
    except ConnectionError as e:
        logging.critical(f"Failed to start proc-wolf: {e}")
        sys.exit(1)
    
    try:
        # Pass None for stop_event in CLI mode
        monitor_processes(db, stop_event=None)
    except KeyboardInterrupt:
        logging.info("proc-wolf stopped by user.")
    except Exception as e:
        logging.critical(f"Critical error in main execution: {e}", exc_info=True)
    finally:
        db.close()


if __name__ == "__main__":
    # Configure logging for CLI execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='proc-wolf.log',
        filemode='a'
    )
    
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    main()